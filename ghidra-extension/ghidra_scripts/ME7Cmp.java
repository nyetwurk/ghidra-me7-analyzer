// Compare a flash window with the same file offset in a second image.
// Args: path address length. path is a raw bin. address is a CPU address in this program.
// Prints this image, the other image, and a pattern with ?? where a byte differs.
// @category ME7
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ME7Cmp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            println("usage: path address length");
            return;
        }
        long addr = Long.decode(args[1].startsWith("0x") || args[1].startsWith("0X") ? args[1] : "0x" + args[1]);
        int length = Integer.decode(args[2]);
        if (addr < 0x800000 || length < 1 || length > 256) {
            println("address length");
            return;
        }
        int off = (int) (addr - 0x800000);
        byte[] other = Files.readAllBytes(Path.of(args[0]));
        if (off + length > other.length) {
            println("other image short");
            return;
        }
        Address at = toAddr(addr);
        byte[] here = new byte[length];
        currentProgram.getMemory().getBytes(at, here);
        StringBuilder a = new StringBuilder();
        StringBuilder b = new StringBuilder();
        StringBuilder pat = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                a.append(' ');
                b.append(' ');
                pat.append(' ');
            }
            int hb = here[i] & 0xFF;
            int ob = other[off + i] & 0xFF;
            a.append(String.format("%02X", hb));
            b.append(String.format("%02X", ob));
            pat.append(hb == ob ? String.format("%02X", hb) : "??");
        }
        println("this  " + a);
        println("other " + b);
        println("pat   " + pat);
    }
}
