// Follow a map immediate to the call that consumes it.
// Args: one or more 16-bit immediates.
// One line: immediate, instruction address, function entry, call distance from
// that entry, call target, the move, and the call. A segment-0 target is also
// printed as the flash copy at 0x800000. The first 12 bytes of each new target
// follow on a line of their own.
// @category ME7
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class ME7MapUse extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Integer> want = new HashSet<>();
        for (String a : getScriptArgs()) {
            long v = Long.decode(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a);
            want.add((int) (v & 0xFFFF));
        }
        Set<Long> seenTarget = new HashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int n = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            long at = ins.getAddress().getOffset();
            if (at < 0x800000) {
                continue;
            }
            Integer imm = immediate(ins, want);
            if (imm == null) {
                continue;
            }
            Instruction call = nextCall(ins);
            Function fn = getFunctionContaining(ins.getAddress());
            long entry = fn == null ? 0 : fn.getEntryPoint().getOffset();
            if (call == null) {
                println(String.format("%04X %X %X - - | %s", imm, at, entry, ins));
                n++;
                continue;
            }
            Address target = callTarget(call);
            long shown = target == null ? 0 : target.getOffset();
            long flash = shown;
            if (shown < 0x10000) {
                flash = 0x800000L + shown;
            }
            long dist = call.getAddress().getOffset() - entry;
            println(String.format("%04X %X %X +%X %X | %s | %s", imm, at, entry, dist, flash, ins, call));
            if (target != null && seenTarget.add(flash)) {
                println("target " + String.format("%X %s", flash, bytes(toAddr(flash), 12)));
            }
            n++;
        }
        println("uses " + n);
    }

    private Integer immediate(Instruction ins, Set<Integer> want) {
        String text = ins.toString().toLowerCase();
        if (!text.startsWith("mov ")) {
            return null;
        }
        int bracket = text.indexOf('[');
        String scan = bracket < 0 ? text : text.substring(0, bracket);
        for (String mark : new String[] {"#", ","}) {
            int at = scan.indexOf(mark);
            if (at < 0) {
                continue;
            }
            int start = at + 1;
            while (start < scan.length() && scan.charAt(start) == ' ') {
                start++;
            }
            int end = start;
            while (end < scan.length() && (Character.isDigit(scan.charAt(end)) || scan.charAt(end) == 'x'
                    || (scan.charAt(end) >= 'a' && scan.charAt(end) <= 'f'))) {
                end++;
            }
            if (end == start) {
                continue;
            }
            try {
                int imm = (int) (Long.decode(scan.substring(start, end)) & 0xFFFF);
                if (want.contains(imm)) {
                    return imm;
                }
            } catch (NumberFormatException e) {
                continue;
            }
        }
        return null;
    }

    private Instruction nextCall(Instruction ins) {
        Instruction p = ins;
        for (int i = 0; i < 16; i++) {
            p = p.getNext();
            if (p == null || p.getAddress().getOffset() < 0x800000) {
                return null;
            }
            if (p.getFlowType().isCall() || callTarget(p) != null) {
                return p;
            }
            String mnem = p.getMnemonicString();
            if (mnem.equalsIgnoreCase("ret") || mnem.equalsIgnoreCase("rets") || mnem.equalsIgnoreCase("jmpa")
                    || mnem.equalsIgnoreCase("jmpi")) {
                return null;
            }
        }
        return null;
    }

    private Address callTarget(Instruction ins) {
        if (ins.getFlowType().isCall()) {
            Address[] flows = ins.getFlows();
            if (flows.length > 0) {
                return flows[0];
            }
        }
        for (Reference r : ins.getReferencesFrom()) {
            if (r.getReferenceType() == RefType.UNCONDITIONAL_CALL || r.getReferenceType() == RefType.CONDITIONAL_CALL) {
                return r.getToAddress();
            }
        }
        return null;
    }

    private String bytes(Address at, int n) throws Exception {
        byte[] raw = new byte[n];
        currentProgram.getMemory().getBytes(at, raw);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            if (i > 0) {
                hex.append(' ');
            }
            hex.append(String.format("%02X", raw[i] & 0xFF));
        }
        return hex.toString();
    }
}
