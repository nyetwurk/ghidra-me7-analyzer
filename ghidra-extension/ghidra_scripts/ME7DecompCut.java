// Decompile a function, stopping before an address the decompiler cannot represent.
// Arguments: entry end. The body is entry through end, inclusive. The full
// function is restored afterwards, so the saved program is unchanged.
// @category ME7
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ME7DecompCut extends GhidraScript {
    private Address addr(String a) {
        return toAddr(Long.decode(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Address entry = addr(args[0]);
        Address end = addr(args[1]);
        Function full = getFunctionAt(entry);
        Address fullEnd = full == null ? null : full.getBody().getMaxAddress();
        if (full != null) {
            removeFunction(full);
        }
        AddressSet body = new AddressSet(entry, end);
        Function part = currentProgram.getFunctionManager().createFunction(
            "FUN_" + entry, entry, body, SourceType.USER_DEFINED);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        println("==================== " + entry + "-" + end + " body " + part.getBody().getMinAddress() + "-" + part.getBody().getMaxAddress());
        DecompileResults res = di.decompileFunction(part, 120, monitor);
        println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "decompile failed: " + res.getErrorMessage());
        di.dispose();
        removeFunction(part);
        if (fullEnd != null) {
            disassemble(entry);
            createFunction(entry, null);
        }
    }
}
