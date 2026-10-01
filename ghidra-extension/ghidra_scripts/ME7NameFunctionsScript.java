//Name default-named functions from the labeled RAM variables they write and the labeled
//flash maps they read: MODULE_var when an optional module TSV (name, module[,module...])
//attributes the outputs to a module, else set_var; readers only become MODULE_uses_MAP or
//uses_MAP. A non-function label at the entry wins. Then, repeatedly, an unnamed function
//called from a single named function becomes caller_subN, and one whose named callees have
//modules becomes MODULE_caller. Writes the evidence to the plate comment; reruns only
//rename functions still carrying that comment, so names set by hand are kept.
//Headless: script arguments are the module TSV path and/or "dry" (print names, outputs,
//and the functions left unnamed, without changing the program).
//@category ME7
//@menupath Tools.ME7.Name Functions

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;

public class ME7NameFunctionsScript extends GhidraScript {

	private static final String MARK = "ME7NameFunctions:";
	private static final long FLASH = 0x800000;
	private static final Pattern CORE =
		Pattern.compile("PSW|DPP[0-3]|CP|SP|MD[HLC]|STK(OV|UN)|SYSCON|ZEROS|ONES|IP");

	private final Map<String, String[]> modules = new HashMap<>();
	private final Map<Address, Integer> readers = new HashMap<>();
	private final Set<String> taken = new HashSet<>();
	private SymbolTable st;
	private MemoryBlock flash;
	private boolean dry;
	private String lastMod;

	@Override
	protected void run() throws Exception {
		File tsv = null;
		for (String a : getScriptArgs()) {
			if (a.equals("dry")) {
				dry = true;
			}
			else {
				tsv = new File(a);
			}
		}
		if (tsv == null && !isRunningHeadless()) {
			try {
				tsv = askFile("Module TSV (cancel to skip)", "Use");
			}
			catch (CancelledException e) {
				// no module attribution
			}
		}
		if (tsv != null) {
			List<String> lines = Files.readAllLines(tsv.toPath(), StandardCharsets.UTF_8);
			for (String line : lines.subList(1, lines.size())) {
				String[] f = line.split("\t");
				if (f.length >= 2) {
					modules.put(f[0].toLowerCase(), f[1].split(","));
				}
			}
		}
		st = currentProgram.getSymbolTable();
		flash = currentProgram.getMemory().getBlock(toAddr(FLASH));
		FunctionManager fm = currentProgram.getFunctionManager();

		List<Function> todo = new ArrayList<>();
		for (Function f : fm.getFunctions(true)) {
			if (renamable(f)) {
				todo.add(f);
			}
			else {
				taken.add(f.getName());
			}
		}
		Map<Function, String> named = new HashMap<>();
		Map<Function, String> modOf = new HashMap<>();
		int fromLabel = 0, fromData = 0, fromCaller = 0, fromCallee = 0;
		for (Function f : todo) {
			monitor.checkCancelled();
			String n = entryLabel(f);
			if (n != null) {
				fromLabel++;
			}
			else {
				n = fromData(f);
				if (n == null) {
					continue;
				}
				fromData++;
				if (lastMod != null) {
					modOf.put(f, lastMod);
				}
			}
			named.put(f, rename(f, n));
		}
		Map<Function, Integer> subs = new HashMap<>();
		for (boolean changed = true; changed;) {
			changed = false;
			for (Function f : todo) {
				if (named.containsKey(f)) {
					continue;
				}
				Set<Function> callers = f.getCallingFunctions(monitor);
				Function c = callers.size() == 1 ? callers.iterator().next() : null;
				String cn = c == null || c == f ? null
						: named.getOrDefault(c, renamable(c) ? null : c.getName());
				if (cn != null) {
					int k = subs.merge(c, 1, Integer::sum);
					named.put(f, rename(f, cn + "_sub" + k));
					comment(f, "called only from " + cn);
					if (modOf.containsKey(c)) {
						modOf.put(f, modOf.get(c));
					}
					fromCaller++;
					changed = true;
					continue;
				}
				Map<String, Integer> votes = new TreeMap<>();
				List<String> callees = new ArrayList<>();
				for (Function g : f.getCalledFunctions(monitor)) {
					if (named.containsKey(g) || !renamable(g)) {
						callees.add(named.getOrDefault(g, g.getName()));
						if (modOf.containsKey(g)) {
							votes.merge(modOf.get(g), 1, Integer::sum);
						}
					}
				}
				String mod = argmax(votes);
				if (mod != null) {
					named.put(f, rename(f, mod + "_caller"));
					comment(f, "calls " + String.join(", ", callees));
					modOf.put(f, mod);
					fromCallee++;
					changed = true;
				}
			}
		}
		for (Function f : todo) {
			if (named.containsKey(f)) {
				continue;
			}
			if (dry) {
				println(String.format("unnamed %s size=%d callers=%d callees=%d",
					f.getEntryPoint(), f.getBody().getNumAddresses(),
					f.getCallingFunctions(monitor).size(), f.getCalledFunctions(monitor).size()));
			}
			else if (f.getSymbol().getSource() != SourceType.DEFAULT) {
				f.setName(null, SourceType.DEFAULT);
				f.setComment(null);
			}
		}
		println(String.format(
			"ME7NameFunctions: %d of %d default-named functions named " +
				"(%d entry label, %d data, %d sole caller, %d callees)%s",
			named.size(), todo.size(), fromLabel, fromData, fromCaller, fromCallee,
			dry ? " [dry run]" : ""));
	}

	private void comment(Function f, String text) {
		if (dry) {
			println(f.getEntryPoint() + " " + MARK + " " + text);
		}
		else {
			f.setComment(MARK + " " + text);
		}
	}

	private boolean renamable(Function f) {
		SourceType s = f.getSymbol().getSource();
		return s == SourceType.DEFAULT ||
			s == SourceType.ANALYSIS && f.getComment() != null && f.getComment().startsWith(MARK);
	}

	private String rename(Function f, String base) throws Exception {
		String n = base;
		for (int i = 2; taken.contains(n); i++) {
			n = base + "_" + i;
		}
		taken.add(n);
		if (dry) {
			println(String.format("%s %s -> %s", f.getEntryPoint(), f.getName(), n));
		}
		else {
			f.setName(n, SourceType.ANALYSIS);
		}
		return n;
	}

	/** Name of a non-default, non-function label at the entry, if any. */
	private String entryLabel(Function f) {
		for (Symbol s : st.getSymbols(f.getEntryPoint())) {
			if (s.getSymbolType() == SymbolType.LABEL && s.getSource() != SourceType.DEFAULT) {
				return s.getName();
			}
		}
		return null;
	}

	private String fromData(Function f) throws Exception {
		Set<Address> out = new LinkedHashSet<>();
		Set<Address> maps = new LinkedHashSet<>();
		for (Instruction insn : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			for (Reference r : insn.getReferencesFrom()) {
				Address t = r.getToAddress();
				if (!r.isMemoryReference() || label(t) == null) {
					continue;
				}
				boolean inFlash = flash != null && flash.contains(t);
				if (!inFlash && r.getReferenceType().isWrite()) {
					out.add(t);
				}
				else if (inFlash) {
					maps.add(t);
				}
			}
		}
		Set<Address> sfr = new LinkedHashSet<>();
		for (Address a : out) {
			long o = a.getOffset();
			if (o >= 0xF000 && o < 0xF200 || o >= 0xFE00 && o < 0x10000) {
				sfr.add(a);
			}
		}
		if (sfr.size() < out.size() || !maps.isEmpty()) {
			out.removeAll(sfr);
		}
		if (out.isEmpty() && maps.isEmpty()) {
			return null;
		}
		Map<String, Double> votes = new TreeMap<>();
		for (Address a : out) {
			vote(votes, label(a), 2);
		}
		for (Address a : maps) {
			vote(votes, label(a), 1);
		}
		String mod = argmax(votes);
		String n;
		if (!out.isEmpty()) {
			Address p = null;
			for (Address a : out) {
				if (p == null || rank(a) > rank(p)) {
					p = a;
				}
			}
			n = (mod != null ? mod + "_" : "set_") + label(p);
		}
		else {
			Address p = maps.iterator().next();
			for (Address a : maps) {
				if (mod != null && List.of(modulesOf(label(a))).contains(mod)) {
					p = a;
					break;
				}
			}
			n = (mod != null ? mod + "_" : "") + "uses_" + label(p);
		}
		comment(f, "out " + names(out) + "; maps " + names(maps));
		lastMod = mod;
		return n;
	}

	private void vote(Map<String, Double> votes, String name, double w) {
		String[] m = modulesOf(name);
		for (String s : m) {
			votes.merge(s, w / m.length, Double::sum);
		}
	}

	/** Key with the highest value (first in key order on ties), or null if empty. */
	private static <V extends Comparable<V>> String argmax(Map<String, V> votes) {
		String best = null;
		for (Map.Entry<String, V> e : votes.entrySet()) {
			if (best == null || e.getValue().compareTo(votes.get(best)) > 0) {
				best = e.getKey();
			}
		}
		return best;
	}

	private String[] modulesOf(String name) {
		return modules.getOrDefault(name.toLowerCase(), new String[0]);
	}

	/** Primary label name at a, if it is a global non-default label other than a core register. */
	private String label(Address a) {
		Symbol s = st.getPrimarySymbol(a);
		if (s == null || s.getSource() == SourceType.DEFAULT ||
			s.getSymbolType() != SymbolType.LABEL || !s.getParentNamespace().isGlobal()) {
			return null;
		}
		return CORE.matcher(s.getName()).matches() ? null : s.getName();
	}

	/** Reader count, with bit flags and bit collections ranked below plain variables. */
	private int rank(Address a) {
		String n = label(a);
		boolean flag = n.startsWith("B_") || n.toLowerCase().endsWith("bits");
		return readers(a) + (flag ? 0 : 1 << 20);
	}

	/** Number of distinct functions reading a. */
	private int readers(Address a) {
		return readers.computeIfAbsent(a, k -> {
			Set<Function> fs = new HashSet<>();
			for (Reference r : currentProgram.getReferenceManager().getReferencesTo(k)) {
				Function f = getFunctionContaining(r.getFromAddress());
				if (f != null && r.getReferenceType().isRead()) {
					fs.add(f);
				}
			}
			return fs.size();
		});
	}

	private String names(Set<Address> as) {
		List<String> l = new ArrayList<>();
		for (Address a : as) {
			l.add(label(a));
		}
		return l.isEmpty() ? "-" : String.join(", ", l);
	}
}
