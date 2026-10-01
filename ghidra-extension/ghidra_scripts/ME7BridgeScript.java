//Read-only localhost HTTP bridge to the open program, for an agent working beside the GUI.
//Writes port and token to me7-bridge.json in the project directory. Run again to restart.
//Headless: serves currentProgram until GET /stop.
//@category ME7
//@menupath Tools.ME7.Start Agent Bridge

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class ME7BridgeScript extends GhidraScript {

	private static final String KEY = "me7.bridge";

	private PluginTool tool;
	private Program headlessProgram;
	private String token;
	private final CountDownLatch stopped = new CountDownLatch(1);

	@Override
	protected void run() throws Exception {
		if (shutdown()) {
			println("bridge: stopped previous instance");
		}
		tool = state.getTool();
		headlessProgram = currentProgram;
		byte[] raw = new byte[16];
		new SecureRandom().nextBytes(raw);
		token = HexFormat.of().formatHex(raw);

		HttpServer server =
			HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		server.createContext("/", this::handle);
		server.setExecutor(Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, KEY);
			t.setDaemon(true);
			return t;
		}));
		server.start();
		System.getProperties().put(KEY, server);

		File info = new File(state.getProject().getProjectLocator().getLocation(), "me7-bridge.json");
		int port = server.getAddress().getPort();
		Files.writeString(info.toPath(),
			String.format("{\"port\": %d, \"token\": \"%s\"}%n", port, token));
		println("bridge: http://127.0.0.1:" + port + "/ (token in " + info + ")");
		if (tool == null) {
			stopped.await();
		}
	}

	private void handle(HttpExchange ex) throws IOException {
		Map<String, String> q = query(ex.getRequestURI().getRawQuery());
		String got = ex.getRequestHeaders().getFirst("X-Token");
		int code = 200;
		String body;
		try {
			if (!token.equals(got != null ? got : q.get("token"))) {
				code = 403;
				body = "bad token\n";
			}
			else {
				body = dispatch(ex.getRequestURI().getPath(), q);
			}
		}
		catch (Exception e) {
			code = 400;
			body = e + "\n";
		}
		byte[] out = body.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
		ex.sendResponseHeaders(code, out.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(out);
		}
	}

	private String dispatch(String path, Map<String, String> q) throws Exception {
		if (path.equals("/stop")) {
			new Thread(this::stop).start();
			return "stopping\n";
		}
		Program p = tool == null ? headlessProgram
				: tool.getService(ProgramManager.class).getCurrentProgram();
		if (p == null) {
			return "no program open\n";
		}
		StringBuilder sb = new StringBuilder();
		switch (path) {
			case "/program" -> sb.append(String.format("%s %s %s %s-%s functions=%d%n",
				p.getName(), p.getLanguageID(), p.getCompilerSpec().getCompilerSpecID(),
				p.getMinAddress(), p.getMaxAddress(), p.getFunctionManager().getFunctionCount()));
			case "/location" -> location(p, sb);
			case "/blocks" -> {
				for (MemoryBlock b : p.getMemory().getBlocks()) {
					sb.append(String.format("%-14s %s-%s %s%s%s %s%n", b.getName(), b.getStart(),
						b.getEnd(), b.isRead() ? "r" : "-", b.isWrite() ? "w" : "-",
						b.isExecute() ? "x" : "-", b.getType()));
				}
			}
			case "/bytes" -> {
				byte[] buf = new byte[Integer.decode(q.getOrDefault("len", "64"))];
				int n = p.getMemory().getBytes(addr(p, q), buf);
				sb.append(HexFormat.ofDelimiter(" ").formatHex(buf, 0, n)).append('\n');
			}
			case "/listing" -> {
				int count = Integer.decode(q.getOrDefault("count", "40"));
				for (CodeUnit cu : p.getListing().getCodeUnits(addr(p, q), true)) {
					if (count-- <= 0) {
						break;
					}
					Symbol s = p.getSymbolTable().getPrimarySymbol(cu.getAddress());
					if (s != null) {
						sb.append(s.getName()).append(":\n");
					}
					sb.append(String.format("  %s  %-12s %s", cu.getAddress(),
						HexFormat.of().formatHex(cu.getBytes()), cu));
					String sep = "  ; ";
					for (Reference r : cu.getReferencesFrom()) {
						if (r.isMemoryReference()) {
							Symbol t = p.getSymbolTable().getPrimarySymbol(r.getToAddress());
							sb.append(sep).append(t != null ? t.getName() : r.getToAddress().toString());
							sep = ", ";
						}
					}
					sb.append('\n');
				}
			}
			case "/function" -> {
				Function f = function(p, q);
				sb.append(f.getName()).append(" entry=").append(f.getEntryPoint()).append('\n');
				for (AddressRange r : f.getBody()) {
					sb.append("  ").append(r).append('\n');
				}
			}
			case "/decompile" -> {
				DecompInterface d = new DecompInterface();
				try {
					d.openProgram(p);
					DecompileResults r = d.decompileFunction(function(p, q), 60, TaskMonitor.DUMMY);
					sb.append(r.decompileCompleted() ? r.getDecompiledFunction().getC()
							: "decompile failed: " + r.getErrorMessage() + "\n");
				}
				finally {
					d.dispose();
				}
			}
			case "/xrefs" -> {
				Address a = addr(p, q);
				for (Reference r : p.getReferenceManager().getReferencesTo(a)) {
					sb.append("to   ").append(r.getFromAddress()).append(' ')
							.append(r.getReferenceType()).append('\n');
				}
				for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
					sb.append("from ").append(r.getToAddress()).append(' ')
							.append(r.getReferenceType()).append('\n');
				}
			}
			case "/symbols" -> {
				int limit = Integer.decode(q.getOrDefault("limit", "200"));
				for (Symbol s : p.getSymbolTable()
						.getSymbolIterator("*" + q.getOrDefault("q", "") + "*", false)) {
					if (limit-- <= 0) {
						break;
					}
					sb.append(s.getAddress()).append(' ').append(s.getName()).append('\n');
				}
			}
			default -> sb.append("endpoints: /program /location /blocks /bytes?addr&len "
				+ "/listing?addr&count /function?addr /decompile?addr /xrefs?addr "
				+ "/symbols?q&limit /stop\n");
		}
		return sb.toString();
	}

	private void location(Program p, StringBuilder sb) {
		if (tool == null) {
			sb.append("headless: no GUI location\n");
			return;
		}
		CodeViewerService cv = tool.getService(CodeViewerService.class);
		ProgramLocation loc = Swing.runNow(cv::getCurrentLocation);
		ProgramSelection sel = Swing.runNow(cv::getCurrentSelection);
		if (loc != null) {
			Function f = p.getFunctionManager().getFunctionContaining(loc.getAddress());
			sb.append(loc.getAddress()).append(f != null ? " in " + f.getName() : "").append('\n');
		}
		if (sel != null) {
			for (AddressRange r : sel) {
				sb.append("selected ").append(r).append('\n');
			}
		}
	}

	private static Address addr(Program p, Map<String, String> q) {
		String s = q.get("addr");
		Address a = s == null ? null : p.getAddressFactory().getAddress(s.replaceFirst("^0x", ""));
		if (a == null) {
			throw new IllegalArgumentException("bad or missing addr");
		}
		return a;
	}

	private static Function function(Program p, Map<String, String> q) {
		Function f = p.getFunctionManager().getFunctionContaining(addr(p, q));
		if (f == null) {
			throw new IllegalArgumentException("no function at " + q.get("addr"));
		}
		return f;
	}

	private static Map<String, String> query(String raw) {
		Map<String, String> out = new HashMap<>();
		if (raw != null) {
			for (String kv : raw.split("&")) {
				String[] parts = kv.split("=", 2);
				out.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
					parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
			}
		}
		return out;
	}

	private void stop() {
		shutdown();
		Msg.info(this, "bridge: stopped");
		stopped.countDown();
	}

	/** Stops the running bridge, if any, letting in-flight responses finish (up to 1 s). */
	private static boolean shutdown() {
		if (!(System.getProperties().remove(KEY) instanceof HttpServer s)) {
			return false;
		}
		s.stop(1);
		((ExecutorService) s.getExecutor()).shutdown();
		return true;
	}
}
