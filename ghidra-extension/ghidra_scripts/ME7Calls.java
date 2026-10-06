// List CALLS whose target is one of the address arguments.
// One line per call: function entry, byte distance, call address, target, the instructions in front of the call.
// @category ME7
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class ME7Calls extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Long> want = new HashSet<>();
        java.util.List<Long> entries = new java.util.ArrayList<>();
        for (String a : getScriptArgs()) {
            if (a.startsWith("entry:")) {
                entries.add(Long.decode(a.substring(6)));
                continue;
            }
            want.add(Long.decode(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a));
        }
        for (long e : entries) {
            Address addr = toAddr(e);
            Function existing = getFunctionAt(addr);
            if (existing == null) {
                createFunction(addr, null);
            }
        }
        var it = currentProgram.getListing().getInstructions(true);
        int n = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            long at = ins.getAddress().getOffset();
            if (at < 0x800000) {
                continue;
            }
            boolean call = ins.getFlowType().isCall();
            Address target = null;
            if (call) {
                Address[] flows = ins.getFlows();
                if (flows.length > 0) {
                    target = flows[0];
                }
            }
            if (target == null) {
                for (Reference r : ins.getReferencesFrom()) {
                    if (r.getReferenceType() == RefType.UNCONDITIONAL_CALL || r.getReferenceType() == RefType.CONDITIONAL_CALL) {
                        target = r.getToAddress();
                        call = true;
                        break;
                    }
                }
            }
            if (!call || target == null || !wanted(want, target.getOffset())) {
                continue;
            }
            Function fn = getFunctionContaining(ins.getAddress());
            Instruction entryIns = ins;
            Instruction prev = ins.getPrevious();
            for (int steps = 0; prev != null && steps < 800; steps++) {
                if (prev.getAddress().getOffset() < 0x800000) {
                    break;
                }
                String mnem = prev.getMnemonicString();
                if (mnem.equalsIgnoreCase("rets") || mnem.equalsIgnoreCase("ret")) {
                    Instruction next = prev.getNext();
                    if (next != null) {
                        entryIns = next;
                    }
                    break;
                }
                prev = prev.getPrevious();
            }
            long entry = fn != null ? fn.getEntryPoint().getOffset() : entryIns.getAddress().getOffset();
            if (entry < 0x800000) {
                entry = entryIns.getAddress().getOffset();
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
            long shown = target.getOffset();
            if (shown < 0x10000 && want.contains(0x800000L + shown)) {
                shown = 0x800000L + shown;
            }
            println(String.format("%X %X +%X %X | %s", entry, at, at - entry, shown, before));
            n++;
        }
        println("calls " + n);
    }

    // A CALLS with segment 0 lands in the 32 KB mirror. The same word is the flash copy at 0x800000.
    private static boolean wanted(Set<Long> want, long target) {
        if (want.contains(target)) {
            return true;
        }
        return target < 0x10000 && want.contains(0x800000L + target);
    }
}
