//Контроль косвенной адресации копии + дизасм функций, читающих запись A.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class ZmuDump extends GhidraScript {

    private Address a(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    private void dump(String title, long from, long to) {
        println("");
        println("===== " + title + "  0x" + Long.toHexString(from) + ".." + Long.toHexString(to) + " =====");
        Instruction ins = getInstructionAt(a(from));
        while (ins != null && ins.getAddress().getOffset() <= to) {
            println(String.format("  %s  %s", ins.getAddress(), ins.toString()));
            ins = ins.getNext();
        }
    }

    @Override
    public void run() throws Exception {
        // 0x2208 = смещение от записи A (0x1D00) до копии (0x3F08)
        long[] want = {0x2208, 0x3F08, 0x3F00, 0x4002, 0x092C, 0x2200};
        println("");
        println("##### поиск констант, которыми можно ДОСЧИТАТЬ до копии 0x3F08 #####");
        int n = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (int i = 0; i < ins.getNumOperands(); i++) {
                for (Object o : ins.getOpObjects(i)) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        for (long w : want) {
                            if (v == w) {
                                println(String.format("  %s  %-40s  (конст 0x%X)", ins.getAddress(), ins.toString(), w));
                                n++;
                            }
                        }
                    }
                }
            }
        }
        println("  найдено: " + n);

        dump("ENTRY_RESET / старт", 0x20001040L, 0x200010C0L);
        dump("FUN_20001154 (обход цепочки записи A)", 0x20001154L, 0x200011C0L);
        dump("FUN_20001366 (читает 0x1D00)", 0x20001366L, 0x200013F2L);
        dump("FUN_20023dc8 (верификатор)", 0x20023DC8L, 0x20023EC0L);
    }
}
