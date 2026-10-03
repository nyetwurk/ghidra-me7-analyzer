// Decompile the functions containing each hex address argument, with callers.
// @category ME7
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class ME7Decomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String a : getScriptArgs()) {
            Address addr = toAddr(Long.decode(a.startsWith("0x") ? a : "0x" + a));
            Function f = getFunctionContaining(addr);
            println("==================== " + a + " -> " + (f == null ? "NO FUNCTION" : f.getName() + " @ " + f.getEntryPoint()));
            if (f == null) {
                continue;
            }
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                println("  caller " + r.getFromAddress() + " " + r.getReferenceType() + (c == null ? "" : " in " + c.getName()));
            }
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "decompile failed: " + res.getErrorMessage());
        }
        di.dispose();
    }
}
