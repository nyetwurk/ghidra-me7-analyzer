// Search flash for a byte pattern. "??" or "XX" is a wildcard byte.
// One argument: the pattern, hex, spaces allowed.
// One line per hit: CPU address, file offset, and the function that contains it.
// @category ME7
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class ME7Pat extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (getScriptArgs().length != 1) {
            println("usage: pattern");
            return;
        }
        String hex = getScriptArgs()[0].replace(" ", "").replace("?", "X").toUpperCase();
        if (hex.length() == 0 || hex.length() % 2 != 0) {
            println("pattern length");
            return;
        }
        int n = hex.length() / 2;
        byte[] pat = new byte[n];
        byte[] mask = new byte[n];
        for (int i = 0; i < n; i++) {
            int hi = nib(hex.charAt(i * 2));
            int lo = nib(hex.charAt(i * 2 + 1));
            if (hi < -1 || lo < -1) {
                println("pattern byte " + hex.substring(i * 2, i * 2 + 2));
                return;
            }
            if (hi >= 0) {
                pat[i] |= (byte) (hi << 4);
                mask[i] |= (byte) 0xF0;
            }
            if (lo >= 0) {
                pat[i] |= (byte) lo;
                mask[i] |= (byte) 0x0F;
            }
        }
        Address base = toAddr(0x800000);
        MemoryBlock block = currentProgram.getMemory().getBlock(base);
        if (block == null) {
            println("no flash");
            return;
        }
        byte[] img = new byte[(int) block.getSize()];
        block.getBytes(base, img);
        int hits = 0;
        for (int i = 0; i + n <= img.length && !monitor.isCancelled(); i += 2) {
            boolean ok = true;
            for (int j = 0; j < n; j++) {
                if ((img[i + j] & mask[j]) != (pat[j] & mask[j])) {
                    ok = false;
                    break;
                }
            }
            if (!ok) {
                continue;
            }
            Address hit = toAddr(0x800000L + i);
            Function fn = getFunctionContaining(hit);
            println(String.format("%X %X %s", 0x800000L + i, i, fn == null ? "-" : fn.getName()));
            hits++;
        }
        println("hits " + hits);
    }

    private static int nib(char c) {
        if (c == 'X') {
            return -1;
        }
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -2;
    }
}
