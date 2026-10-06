// List instructions whose scalar operand is one of the address arguments.
// One line: instruction address, function entry, function name, instruction.
// @category ME7
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class ME7Imm extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Long> want = new HashSet<>();
        for (String a : getScriptArgs()) {
            want.add(Long.decode(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a) & 0xFFFF);
        }
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int n = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            long at = ins.getAddress().getOffset();
            if (at < 0x800000) {
                continue;
            }
            boolean hit = false;
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object obj : ins.getOpObjects(op)) {
                    if (obj instanceof Scalar && want.contains(((Scalar) obj).getUnsignedValue() & 0xFFFF)) {
                        hit = true;
                    }
                }
            }
            if (!hit) {
                continue;
            }
            Function fn = getFunctionContaining(ins.getAddress());
            long entry = fn == null ? 0 : fn.getEntryPoint().getOffset();
            println(String.format("%X %X %s %s", at, entry, fn == null ? "-" : fn.getName(), ins));
            n++;
        }
        println("imms " + n);
    }
}
