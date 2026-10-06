// List CALLS inside a function. The entry is created when it is not a function yet.
// Args: one or more entry addresses.
// One line: entry, byte distance, target, and the four instructions before the call.
// A segment-0 target in the first 64K is printed as the flash copy at 0x800000.
// @category ME7
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class ME7CallsIn extends GhidraScript {
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
            long start = fn.getEntryPoint().getOffset();
            println(String.format("function %X %s", start, made));
            InstructionIterator it = currentProgram.getListing().getInstructions(fn.getBody(), true);
            int n = 0;
            while (it.hasNext() && !monitor.isCancelled()) {
                Instruction ins = it.next();
                Address target = null;
                if (ins.getFlowType().isCall()) {
                    Address[] flows = ins.getFlows();
                    if (flows.length > 0) {
                        target = flows[0];
                    }
                }
                if (target == null) {
                    for (Reference r : ins.getReferencesFrom()) {
                        if (r.getReferenceType() == RefType.UNCONDITIONAL_CALL || r.getReferenceType() == RefType.CONDITIONAL_CALL) {
                            target = r.getToAddress();
                            break;
                        }
                    }
                }
                if (target == null) {
                    continue;
                }
                long at = ins.getAddress().getOffset();
                long shown = target.getOffset();
                if (shown < 0x10000) {
                    shown = 0x800000L + shown;
                }
                StringBuilder before = new StringBuilder();
                Instruction p = ins;
                String[] window = new String[4];
                for (int i = 3; i >= 0; i--) {
                    p = p.getPrevious();
                    window[i] = p == null ? "" : p.toString();
                }
                for (String w : window) {
                    if (w.length() == 0) {
                        continue;
                    }
                    if (before.length() > 0) {
                        before.append(" | ");
                    }
                    before.append(w);
                }
                println(String.format("%X +%X %X | %s", start, at - start, shown, before));
                n++;
            }
            println("calls " + n);
        }
    }
}
