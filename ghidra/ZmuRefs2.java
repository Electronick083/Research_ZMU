//Полный охват: какие адреса config-чипа (0x0000..0x7FFF) реально трогает КОД.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import java.util.TreeMap;
import java.util.Map;

public class ZmuRefs2 extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("");
        println("################ ZmuRefs2 ################");

        TreeMap<Long, Integer> pages = new TreeMap<>();
        java.util.List<String> hi_lines = new java.util.ArrayList<>();
        long maxTouched = -1;
        int codeRefs = 0;

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Reference r : ins.getReferencesFrom()) {
                Address to = r.getToAddress();
                if (!to.getAddressSpace().equals(
                        currentProgram.getAddressFactory().getDefaultAddressSpace())) continue;
                long v = to.getOffset();
                if (v < 0 || v > 0x7FFF) continue;
                codeRefs++;
                pages.merge(v >> 8, 1, Integer::sum);
                if (v > maxTouched) maxTouched = v;
                if (v >= 0x2200) {
                    Function f = getFunctionContaining(ins.getAddress());
                    hi_lines.add(String.format("    0x%04X  из %s  %-34s  %s  функция=%s",
                            v, ins.getAddress(), ins.toString(), r.getReferenceType(),
                            f != null ? f.getName() : "-"));
                }
            }
        }

        println("ссылок ИЗ ИНСТРУКЦИЙ в 0x0000..0x7FFF: " + codeRefs);
        println("максимальный затронутый адрес: 0x" + Long.toHexString(maxTouched));
        println("");
        println("--- страницы, затронутые КОДОМ ---");
        for (Map.Entry<Long, Integer> e : pages.entrySet()) {
            println(String.format("  0x%04X..0x%04X : %d", e.getKey() << 8, (e.getKey() << 8) | 0xFF, e.getValue()));
        }
        println("");
        println("--- все обращения кода к адресам >= 0x2200 ---");
        if (hi_lines.isEmpty()) println("    (нет)");
        for (String hl : hi_lines) println(hl);

        // непосредственные константы 0x3F08 / 0x3F00 / 0x4002 / 0x092C в операндах
        println("");
        println("--- инструкции с непосредственной константой 3F08/3F00/4002/092C ---");
        int imm = 0;
        it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (int i = 0; i < ins.getNumOperands(); i++) {
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        if (v == 0x3F08 || v == 0x3F00 || v == 0x4002 || v == 0x092C
                                || v == 0x40020000L || v == 0x00003F08L) {
                            println(String.format("    %s  %s", ins.getAddress(), ins.toString()));
                            imm++;
                        }
                    }
                }
            }
        }
        if (imm == 0) println("    (нет)");
        println("################ конец ################");
    }
}
