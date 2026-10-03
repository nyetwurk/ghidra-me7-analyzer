// List every reference to each hex address argument (and +1), with type, function, and instruction.
// @category ME7
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class ME7Xref extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            long v = Long.decode(a.startsWith("0x") ? a : "0x" + a);
            for (long o = 0; o < 2; o++) {
                Address addr = toAddr(v + o);
                println("==== refs to " + addr);
                for (Reference r : getReferencesTo(addr)) {
                    Address f = r.getFromAddress();
                    Function fn = getFunctionContaining(f);
                    Instruction ins = getInstructionAt(f);
                    println(String.format("  %s %-6s %-28s %s", f, r.getReferenceType().getName(),
                        fn == null ? "-" : fn.getName(), ins == null ? "" : ins.toString()));
                }
            }
        }
    }
}
