// Print flash bytes at a CPU address. The address need not be a function.
// Args: address [length]. Length defaults to 16.
// @category ME7
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class ME7Bytes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            println("usage: address [length]");
            return;
        }
        long addr = Long.decode(args[0].startsWith("0x") || args[0].startsWith("0X") ? args[0] : "0x" + args[0]);
        int length = args.length == 2 ? Integer.decode(args[1]) : 16;
        if (length < 1 || length > 4096) {
            println("length");
            return;
        }
        Address at = toAddr(addr);
        byte[] raw = new byte[length];
        currentProgram.getMemory().getBytes(at, raw);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            if (i > 0) {
                hex.append(' ');
            }
            hex.append(String.format("%02X", raw[i] & 0xFF));
        }
        println(String.format("%X %s", addr, hex));
    }
}
