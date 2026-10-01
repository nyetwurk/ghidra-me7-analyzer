//@category ME7
//@menupath Tools.ME7.Set Up Memory Map

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * ME7 memory map for a flash image loaded at 0x800000 (BinaryLoader).
 * Usable as an analyzeHeadless -preScript. Finds everything from the image bytes:
 * <ul>
 * <li>flash_mirror: 32 KB at 0x0 mapped to flash (segment 0 CALLS)</li>
 * <li>DPP0-3 from the most common full MOV DPP0..3,#imm block with DPP0 != 0</li>
 * <li>kernel_ram: 32 KB at 0x380000 mapped to the flash offset where the most
 * CALLS 0x38:xxxx targets land right after a RETS</li>
 * <li>seeds: vector table slots, the matched CALLS 0x38 targets, and flash CALLS
 * targets that start right after a RET/RETS</li>
 * </ul>
 */
public class ME7SetupScript extends GhidraScript {

	private static final long FLASH = 0x800000;
	private static final long MIRROR_SIZE = 0x8000;
	private static final int RAM_SEG = 0x38;
	private static final long RAM_SIZE = 0x8000;
	private static final int[] DEFAULT_DPP = { 0x0204, 0x0205, 0x00E0, 0x0003 };

	@Override
	protected void run() throws Exception {
		Memory mem = currentProgram.getMemory();
		AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Address flash = space.getAddress(FLASH);
		MemoryBlock flashBlock = mem.getBlock(flash);
		if (flashBlock == null || !flashBlock.getStart().equals(flash)) {
			printerr("No memory block starting at 0x800000; import with -loader-baseAddr 0x800000");
			return;
		}
		byte[] img = new byte[(int) flashBlock.getSize()];
		flashBlock.getBytes(flash, img);
		println(String.format("flash: %d KB at 0x%06X", img.length / 1024, FLASH));

		if (mem.getBlock(space.getAddress(0)) == null) {
			MemoryBlock b = mem.createByteMappedBlock("flash_mirror", space.getAddress(0), flash,
				Math.min(MIRROR_SIZE, img.length), false);
			b.setRead(true);
			b.setExecute(true);
		}

		int[] dpp = findDpp(img);
		if (dpp == null) {
			dpp = DEFAULT_DPP;
			println("dpp: no full DPP0-3 init block; using ME7 defaults");
		}
		println(String.format("dpp: DPP0=0x%04X DPP1=0x%04X DPP2=0x%04X DPP3=0x%04X",
			dpp[0], dpp[1], dpp[2], dpp[3]));

		long ramBase = (long) RAM_SEG << 16;
		Address ram = space.getAddress(ramBase);
		List<Integer> seeds = new ArrayList<>();
		long[] sweep = sweepCopyOffset(img, RAM_SEG, (int) RAM_SIZE, seeds);
		if (sweep == null) {
			println("kernel_ram: no CALLS 0x38 targets; not mapped");
		}
		else {
			long k = sweep[0];
			boolean confident = sweep[1] >= 10 && sweep[1] >= 2 * sweep[3];
			println(String.format(
				"kernel_ram: 0x%02Xxxxx = file xxxx+0x%X (%d/%d CALLS targets after RETS, runner-up %d)%s",
				RAM_SEG, k, sweep[1], sweep[2], sweep[3], confident ? "" : "; low confidence, not mapped"));
			if (!confident) {
				seeds.clear();
			}
			else if (mem.getBlock(ram) == null) {
				MemoryBlock b = mem.createByteMappedBlock("kernel_ram", ram, flash.add(k),
					Math.min(RAM_SIZE, img.length - k), false);
				b.setRead(true);
				b.setWrite(true);
				b.setExecute(true);
			}
		}

		ProgramContext ctx = currentProgram.getProgramContext();
		for (int i = 0; i < 4; i++) {
			Register r = currentProgram.getRegister("DPP" + i);
			if (r == null) {
				printerr("Register DPP" + i + " not found; is the C166 language loaded?");
				continue;
			}
			BigInteger v = BigInteger.valueOf(dpp[i]);
			for (MemoryBlock b : mem.getBlocks()) {
				if (b.isExecute()) {
					ctx.setValue(r, b.getStart(), b.getEnd(), v);
				}
			}
		}

		disassemble(flash);
		for (long v = FLASH + 4; v < FLASH + 0x200; v += 4) {
			disassemble(space.getAddress(v));
		}
		if (mem.getBlock(ram) != null) {
			for (int t : seeds) {
				seedFunction(ram.add(t));
			}
			println("kernel_ram: seeded " + seeds.size() + " functions");
		}
		List<Integer> flashSeeds = flashCallTargets(img);
		for (int t : flashSeeds) {
			seedFunction(flash.add(t));
		}
		println("flash: seeded " + flashSeeds.size() + " CALLS targets after RET/RETS");
		setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "true");
		println("ME7Setup done");
	}

	private void seedFunction(Address a) {
		disassemble(a);
		if (getFunctionAt(a) == null) {
			createFunction(a, null);
		}
	}

	private static int u16(byte[] d, int i) {
		return (d[i] & 0xFF) | ((d[i + 1] & 0xFF) << 8);
	}

	/** Most common contiguous E6 00/01/02/03 block, preferring DPP0 != 0 (boot reset is 0). */
	private static int[] findDpp(byte[] d) {
		Map<Long, Integer> counts = new HashMap<>();
		for (int i = 0; i + 16 <= d.length; i += 2) {
			boolean ok = true;
			for (int r = 0; r < 4 && ok; r++) {
				ok = (d[i + 4 * r] & 0xFF) == 0xE6 && d[i + 4 * r + 1] == r;
			}
			if (ok) {
				long key = 0;
				for (int r = 0; r < 4; r++) {
					key = (key << 16) | u16(d, i + 4 * r + 2);
				}
				counts.merge(key, 1, Integer::sum);
			}
		}
		Long best = null;
		for (Map.Entry<Long, Integer> e : counts.entrySet()) {
			if (best == null || rank(e.getKey(), e.getValue()) > rank(best, counts.get(best))) {
				best = e.getKey();
			}
		}
		if (best == null) {
			return null;
		}
		int[] out = new int[4];
		for (int r = 3; r >= 0; r--) {
			out[r] = (int) (best & 0xFFFF);
			best >>>= 16;
		}
		return out;
	}

	private static long rank(long key, int count) {
		boolean dpp0Nonzero = (key >>> 48) != 0;
		return (dpp0Nonzero ? 1L << 32 : 0) + count;
	}

	private static boolean afterReturn(byte[] d, int p) {
		return p >= 2 && d[p - 1] == 0 && ((d[p - 2] & 0xFF) == 0xDB || (d[p - 2] & 0xFF) == 0xCB);
	}

	/** Even CALLS 0x80+seg:xxxx targets inside the image that start right after a RET or RETS. */
	private static List<Integer> flashCallTargets(byte[] d) {
		TreeSet<Integer> out = new TreeSet<>();
		for (int i = 0; i + 4 <= d.length; i += 2) {
			int seg = (d[i + 1] & 0xFF) - (int) (FLASH >> 16);
			if ((d[i] & 0xFF) == 0xDA && seg >= 0) {
				int t = (seg << 16) | u16(d, i + 2);
				if (t < d.length && (t & 1) == 0 && afterReturn(d, t)) {
					out.add(t);
				}
			}
		}
		return new ArrayList<>(out);
	}

	/**
	 * Returns {offset, matched, targets, runnerUp} and fills seeds with matched
	 * targets, or null if there are no CALLS seg:xxxx targets.
	 */
	private static long[] sweepCopyOffset(byte[] d, int seg, int size, List<Integer> seeds) {
		TreeSet<Integer> targets = new TreeSet<>();
		List<Integer> rets = new ArrayList<>();
		for (int i = 0; i + 4 <= d.length; i += 2) {
			if ((d[i] & 0xFF) == 0xDA && (d[i + 1] & 0xFF) == seg) {
				int t = u16(d, i + 2);
				if (t < size) {
					targets.add(t);
				}
			}
			if ((d[i] & 0xFF) == 0xDB && d[i + 1] == 0) {
				rets.add(i + 2);
			}
		}
		if (targets.isEmpty()) {
			return null;
		}
		Map<Integer, Integer> counts = new HashMap<>();
		int limit = d.length - size;
		for (int t : targets) {
			for (int r : rets) {
				int k = r - t;
				if (k >= 0 && k <= limit) {
					counts.merge(k, 1, Integer::sum);
				}
			}
		}
		int bestK = -1;
		int best = 0;
		int second = 0;
		for (Map.Entry<Integer, Integer> e : counts.entrySet()) {
			int n = e.getValue();
			if (n > best || (n == best && e.getKey() < bestK)) {
				second = Math.max(second, best);
				best = n;
				bestK = e.getKey();
			}
			else if (n > second) {
				second = n;
			}
		}
		if (bestK < 0) {
			return null;
		}
		for (int t : targets) {
			int p = t + bestK;
			if (p >= 2 && (d[p - 2] & 0xFF) == 0xDB && d[p - 1] == 0) {
				seeds.add(t);
			}
		}
		return new long[] { bestK, best, targets.size(), second };
	}
}
