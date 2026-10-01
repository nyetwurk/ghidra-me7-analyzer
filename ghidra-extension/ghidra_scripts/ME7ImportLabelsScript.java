//Import labels from a TSV with header columns addr, name, size, comment (addr in hex).
//The first name at an address becomes primary; size 1 or 2 applies byte/word data where
//the address is still undefined. Then adds data references from MOV Rn,#imm map pointers
//(page from a following MOV Rm,#page, else from DPP) to imported labels in flash.
//Headless: pass the TSV path as the script argument.
//@category ME7
//@menupath Tools.ME7.Import Labels

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ME7ImportLabelsScript extends GhidraScript {

	private static final long FLASH = 0x800000;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File file = args.length > 0 ? new File(args[0]) : askFile("Labels TSV", "Import");
		List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
		List<String> cols = Arrays.asList(lines.get(0).split("\t"));
		int ai = cols.indexOf("addr"), ni = cols.indexOf("name");
		int si = cols.indexOf("size"), ci = cols.indexOf("comment");
		if (ai < 0 || ni < 0) {
			printerr("TSV needs addr and name columns");
			return;
		}
		SymbolTable st = currentProgram.getSymbolTable();
		Listing listing = currentProgram.getListing();
		int labels = 0, typed = 0, skipped = 0;
		for (String line : lines.subList(1, lines.size())) {
			monitor.checkCancelled();
			String[] f = line.split("\t", -1);
			Address a = toAddr(Long.decode(f[ai]));
			if (!currentProgram.getMemory().contains(a)) {
				skipped++;
				continue;
			}
			Symbol prev = st.getPrimarySymbol(a);
			Symbol s = st.createLabel(a, f[ni], SourceType.IMPORTED);
			if (prev == null || prev.getSource() == SourceType.DEFAULT) {
				s.setPrimary();
			}
			labels++;
			if (ci >= 0 && !f[ci].isEmpty()) {
				String old = listing.getComment(CommentType.EOL, a);
				String add = f[ni] + ": " + f[ci];
				if (old == null || !old.contains(add)) {
					listing.setComment(a, CommentType.EOL, old == null ? add : old + "\n" + add);
				}
			}
			int size = si >= 0 && !f[si].isEmpty() ? Integer.parseInt(f[si]) : 0;
			if ((size == 1 || size == 2) && listing.isUndefined(a, a.add(size - 1))) {
				try {
					createData(a, size == 1 ? ByteDataType.dataType : WordDataType.dataType);
					typed++;
				}
				catch (Exception e) {
					// address overlaps code or other data
				}
			}
		}
		println(String.format("ME7ImportLabels: %d labels, %d typed, %d outside memory (%s)",
			labels, typed, skipped, file.getName()));
		println("ME7ImportLabels: " + addPointerRefs() + " map pointer references");
	}

	private int addPointerRefs() throws Exception {
		MemoryBlock flash = currentProgram.getMemory().getBlock(toAddr(FLASH));
		if (flash == null) {
			return 0;
		}
		long pageLo = FLASH >> 14, pageHi = flash.getEnd().getOffset() >> 14;
		Register[] dpp = new Register[4];
		for (int i = 0; i < 4; i++) {
			dpp[i] = currentProgram.getRegister("DPP" + i);
		}
		SymbolTable st = currentProgram.getSymbolTable();
		int refs = 0;
		for (Instruction insn : currentProgram.getListing().getInstructions(flash.getStart(), true)) {
			monitor.checkCancelled();
			if (!flash.contains(insn.getAddress())) {
				break;
			}
			long imm = movImm(insn);
			if (imm < 0 || (imm >= pageLo && imm <= pageHi)) {
				continue;
			}
			long page = -1;
			Instruction n = insn.getNext();
			for (int k = 0; k < 3 && n != null && movImm(n) >= 0; k++, n = n.getNext()) {
				long v = movImm(n);
				if (v >= pageLo && v <= pageHi) {
					page = v;
					break;
				}
			}
			long target;
			if (page >= 0 && imm < 0x4000) {
				target = page << 14 | imm;
			}
			else {
				BigInteger p = currentProgram.getProgramContext()
						.getValue(dpp[(int) (imm >> 14)], insn.getAddress(), false);
				if (p == null) {
					continue;
				}
				target = p.longValue() << 14 | (imm & 0x3FFF);
			}
			Address t = toAddr(target);
			Symbol s = st.getPrimarySymbol(t);
			if (flash.contains(t) && s != null && s.getSource() == SourceType.IMPORTED) {
				currentProgram.getReferenceManager()
						.addMemoryReference(insn.getAddress(), t, RefType.DATA, SourceType.ANALYSIS, 1);
				refs++;
			}
		}
		return refs;
	}

	/** Immediate of MOV Rn,#imm16, or -1. */
	private static long movImm(Instruction insn) {
		if (!insn.getMnemonicString().equalsIgnoreCase("mov") || insn.getNumOperands() != 2 ||
			insn.getRegister(0) == null) {
			return -1;
		}
		Scalar s = insn.getScalar(1);
		return s == null ? -1 : s.getUnsignedValue() & 0xFFFF;
	}
}
