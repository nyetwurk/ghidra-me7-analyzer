// Print a function as address, bytes, and the Ghidra instruction.
// The entry is created when it is not a function yet. Pass one or more addresses.
// @category ME7
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class ME7Func extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            if (monitor.isCancelled()) {
                break;
            }
            Address entry = toAddr(Long.decode(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a));
            Function fn = getFunctionAt(entry);
            String made = "existing";
            if (fn == null) {
                fn = createFunction(entry, null);
                made = fn == null ? "failed" : "created";
            }
            if (fn == null) {
                println("no function " + entry);
                continue;
            }
            println(String.format("function %X %s %X-%X", fn.getEntryPoint().getOffset(), made,
                fn.getBody().getMinAddress().getOffset(), fn.getBody().getMaxAddress().getOffset()));
            InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
            int n = 0;
            while (it.hasNext() && n < 500) {
                Instruction ins = it.next();
                byte[] raw = ins.getBytes();
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < raw.length; i++) {
                    if (i > 0) {
                        hex.append(' ');
                    }
                    hex.append(String.format("%02X", raw[i] & 0xFF));
                }
                println(String.format("  %X %s %s", ins.getAddress().getOffset(), hex, ins));
                n++;
            }
            if (n == 500) {
                println("  truncated");
            }
            println("insns " + n);
        }
    }
}
