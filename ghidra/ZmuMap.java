//Строит карту памяти блока ZMU: банк A, config-чип, ОЗУ, I/O.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileInputStream;

public class ZmuMap extends GhidraScript {

    // рабочая папка: сюда run_analysis.sh кладёт bankA.bin/bankB.bin и config.bin
    private static final String SP = "D:\\Claude\\ZMU\\ghidra\\work\\";

    private Address a(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    private void initFromFile(String name, long start, String path, long len) throws Exception {
        File f = new File(path);
        if (!f.exists()) { println("НЕТ ФАЙЛА: " + path); return; }
        FileInputStream is = new FileInputStream(f);
        MemoryBlock b = currentProgram.getMemory().createInitializedBlock(
                name, a(start), is, len, monitor, false);
        b.setRead(true); b.setWrite(false); b.setExecute(true);
        println("блок " + name + " @ " + Long.toHexString(start) + " len " + Long.toHexString(len));
    }

    private void uninit(String name, long start, long len, boolean exec) throws Exception {
        MemoryBlock b = currentProgram.getMemory().createUninitializedBlock(
                name, a(start), len, false);
        b.setRead(true); b.setWrite(true); b.setExecute(exec);
        b.setVolatile(name.startsWith("io") || name.startsWith("hw"));
        println("блок " + name + " @ " + Long.toHexString(start) + " len " + Long.toHexString(len));
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        println("=== ZmuMap: существующие блоки ===");
        for (MemoryBlock b : mem.getBlocks()) {
            println("  " + b.getName() + " " + b.getStart() + ".." + b.getEnd());
        }

        // config-чип AT28C256 #1 — гипотеза: отображён в нижнюю память (код бьёт по abs.w 0x1D00)
        initFromFile("config", 0x00000000L, SP + "config.bin", 0x8000L);
        // банк A ПЗУ
        initFromFile("rom_bankA", 0x30000000L, SP + "bankA.bin", 0x40000L);

        uninit("ram_low",  0x00008000L, 0x00008000L, false);
        uninit("ram_10",   0x10000000L, 0x00100000L, false);
        uninit("ram_40",   0x40000000L, 0x00100000L, false);
        uninit("hw_68302", 0x60000000L, 0x00010000L, false);
        uninit("io_E0",    0xE0000000L, 0x00010000L, false);
        uninit("io_E1",    0xE1000000L, 0x00010000L, false);

        // точка входа
        Address entry = a(0x20001040L);
        createLabel(entry, "ENTRY_RESET", true);
        addEntryPoint(entry);
        disassemble(entry);
        println("=== ZmuMap готово ===");
    }
}
