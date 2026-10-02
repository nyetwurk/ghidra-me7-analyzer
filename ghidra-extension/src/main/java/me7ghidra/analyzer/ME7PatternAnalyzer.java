package me7ghidra.analyzer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Labels hits of the needles in me7-core.yaml (bundled from patterns/; field reference in its
 * header). Requires the keyhana C166 language.
 */
public class ME7PatternAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ME7 Pattern Namer";

	public ME7PatternAnalyzer() {
		super(NAME, "Names ME7 functions (CRC, kernel handlers) from shared YAML needles",
			AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("C166");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		List<Needle> needles;
		try (InputStream in = getClass().getResourceAsStream("/me7-core.yaml")) {
			if (in == null) {
				throw new IOException("not on the extension classpath");
			}
			needles = parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
		}
		catch (IOException | IllegalArgumentException e) {
			log.appendMsg(NAME, "Cannot load me7-core.yaml: " + e);
			return false;
		}

		Memory memory = program.getMemory();
		AddressSetView searchSet = flashOnly(memory).intersect(set);
		int named = 0;
		for (Needle n : needles) {
			List<Address> hits = findAll(memory, searchSet, n, monitor);
			if (n.unique && hits.size() > 1) {
				log.appendMsg(NAME, n.name + ": " + hits.size() + " hits, expected 1; skipped");
				continue;
			}
			for (Address hit : hits) {
				Address label = label(memory, hit, n);
				if (!entryOk(memory, label, n.entryAfter)) {
					log.appendMsg(NAME, n.name + " @ " + label + ": not after RETS/padding; skipped");
					continue;
				}
				try {
					program.getSymbolTable().createLabel(label, n.name, SourceType.ANALYSIS);
				}
				catch (Exception e) {
					log.appendMsg(NAME, "Failed to label " + n.name + ": " + e.getMessage());
					continue;
				}
				if (n.function) {
					new DisassembleCommand(label, null, true).applyTo(program, monitor);
					if (program.getFunctionManager().getFunctionAt(label) == null) {
						new CreateFunctionCmd(label).applyTo(program, monitor);
					}
				}
				named++;
				String delta = n.refOffset == null ? ""
						: String.format(" (delta %+d vs reference)",
							label.subtract(memory.getBlock(label).getStart()) - n.refOffset);
				log.appendMsg(NAME, "Labeled " + n.name + " @ " + label + delta);
			}
		}
		String version = getClass().getPackage().getImplementationVersion();
		log.appendMsg(NAME, "Named " + named + " pattern hit(s) (ME7Ghidra "
			+ (version != null ? version : "dev") + ")");
		return named > 0;
	}

	/**
	 * Initialized, non-mapped blocks only. Byte-mapped views (flash mirror at 0x0, kernel RAM
	 * copy at 0x38xxxx) would otherwise match first.
	 */
	private static AddressSet flashOnly(Memory memory) {
		AddressSet out = new AddressSet();
		for (MemoryBlock b : memory.getBlocks()) {
			if (b.isInitialized() && b.getType() == MemoryBlockType.DEFAULT) {
				out.add(b.getStart(), b.getEnd());
			}
		}
		return out;
	}

	private static List<Address> findAll(Memory memory, AddressSetView set, Needle n,
			TaskMonitor monitor) throws CancelledException {
		List<Address> hits = new ArrayList<>();
		for (AddressRange range : set.getAddressRanges()) {
			Address start = range.getMinAddress();
			Address hit;
			while (start != null
					&& (hit = memory.findBytes(start, range.getMaxAddress(), n.bytes, n.mask, true,
						monitor)) != null) {
				monitor.checkCancelled();
				// C166 instructions are word aligned.
				if ((hit.getOffset() & 1) == 0) {
					hits.add(hit);
				}
				start = hit.next();
			}
		}
		return hits;
	}

	/** With a back_up range, the closest entry to the hit in the range. */
	private static Address label(Memory memory, Address hit, Needle n) {
		if (n.backUpMax != null) {
			for (long b = n.backUp; b <= n.backUpMax; b += 2) {
				Address label = hit.subtract(b);
				if (entryOk(memory, label, n.entryAfter)) {
					return label;
				}
			}
		}
		return hit.subtract(n.backUp);
	}

	private static boolean entryOk(Memory memory, Address label, List<byte[]> entryAfter) {
		for (byte[] want : entryAfter) {
			byte[] got = new byte[want.length];
			try {
				memory.getBytes(label.subtract(want.length), got);
				if (Arrays.equals(got, want)) {
					return true;
				}
			}
			catch (MemoryAccessException | RuntimeException e) {
				// Label at block start; try the next candidate.
			}
		}
		return entryAfter.isEmpty();
	}

	/** Minimal parser for the functions[] subset of me7-core.yaml; avoids a YAML dependency. */
	private static List<Needle> parse(String text) {
		List<Needle> out = new ArrayList<>();
		Matcher m = Pattern.compile("-\\s*name:\\s*(\\S+)([\\s\\S]*?)(?=\\n\\s*-\\s*name:|\\z)")
				.matcher(text);
		while (m.find()) {
			String body = m.group(2);
			Needle n = new Needle(m.group(1));
			String[] toks = field(body, "needle_hex").replaceAll("[\"\\s]", "").split("(?<=\\G..)");
			String maskHex = field(body, "mask_hex");
			byte[] extra = maskHex == null ? null : hex(maskHex);
			if (extra != null && extra.length != toks.length) {
				throw new IllegalArgumentException(n.name + ": mask_hex length differs");
			}
			n.bytes = new byte[toks.length];
			n.mask = new byte[toks.length];
			for (int i = 0; i < toks.length; i++) {
				if (!toks[i].equals("??")) {
					n.mask[i] = extra == null ? (byte) 0xFF : extra[i];
					n.bytes[i] = (byte) (Integer.parseInt(toks[i], 16) & n.mask[i]);
				}
			}
			String v = field(body, "back_up");
			if (v != null && v.startsWith("[")) {
				String[] r = v.replaceAll("[\\[\\]\\s]", "").split(",");
				n.backUp = Long.decode(r[0]);
				n.backUpMax = Long.decode(r[1]);
				if (n.backUp > n.backUpMax || (n.backUpMax - n.backUp) % 2 != 0
						|| field(body, "entry_after") == null) {
					throw new IllegalArgumentException(
						n.name + ": back_up range needs min <= max, even span, entry_after");
				}
			}
			else {
				n.backUp = v == null ? 0 : Long.decode(v);
			}
			v = field(body, "ref_offset");
			n.refOffset = v == null ? null : Long.decode(v);
			n.unique = "true".equals(field(body, "unique"));
			n.function = "true".equals(field(body, "function"));
			v = field(body, "entry_after");
			if (v != null) {
				Matcher q = Pattern.compile("\"([^\"]+)\"").matcher(v);
				while (q.find()) {
					n.entryAfter.add(hex(q.group(1)));
				}
			}
			out.add(n);
		}
		return out;
	}

	/** Raw value of "key: value" in body, or null. */
	private static String field(String body, String key) {
		Matcher f = Pattern.compile("\\n\\s*" + key + ":\\s*(.*)").matcher(body);
		return f.find() ? f.group(1).trim() : null;
	}

	private static byte[] hex(String s) {
		String clean = s.replaceAll("[\"\\s]", "");
		byte[] out = new byte[clean.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	private static final class Needle {
		final String name;
		byte[] bytes;
		byte[] mask;
		long backUp;
		Long backUpMax;
		Long refOffset;
		boolean unique;
		boolean function;
		final List<byte[]> entryAfter = new ArrayList<>();

		Needle(String name) {
			this.name = name;
		}
	}
}
