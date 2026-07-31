//Отчёт: кто ссылается на config-записи A (0x1D00) и B (0x3F08).
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ZmuRefs extends GhidraScript {

    private Address a(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    private void reportRange(String title, long lo, long hi) {
        println("");
        println("========== " + title + "  [0x" + Long.toHexString(lo) + "..0x" + Long.toHexString(hi) + "] ==========");
        int total = 0;
        for (long t = lo; t <= hi; t += 2) {
            Address target = a(t);
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
            while (it.hasNext()) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function f = getFunctionContaining(from);
                Instruction ins = getInstructionAt(from);
                println(String.format("  -> 0x%04X  из %s  %-34s  тип=%s  функция=%s",
                        t, from,
                        ins != null ? ins.toString() : "(данные)",
                        r.getReferenceType(),
                        f != null ? f.getName() : "-"));
                total++;
            }
        }
        println("  ИТОГО ссылок: " + total);
    }

    @Override
    public void run() throws Exception {
        println("");
        println("################ ZmuRefs ################");
        println("функций найдено: " + currentProgram.getFunctionManager().getFunctionCount());
        println("инструкций: " + currentProgram.getListing().getNumInstructions());

        reportRange("ЗАПИСЬ A и её цепочка", 0x1D00, 0x1EFF);
        reportRange("ЗАПИСЬ B и её цепочка", 0x3E00, 0x3FFF);
        reportRange("контроль: вся нижняя страница 0x0000-0x00FF", 0x0000, 0x00FF);
        println("################ конец ################");
    }
}
