//Что реально лежит по заданным адресам: инструкция, данные или середина другой команды.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class ZmuAt extends GhidraScript {

    private static final long[] SPOTS = {
        0x20028294L,   // подозрительный bra -> 0x20029AE0
        0x2002752CL,   // второй кандидат (цель нечётная, заведомо ложный)
    };

    @Override
    public void run() throws Exception {
        println("");
        println("################ ZmuAt ################");
        for (long spot : SPOTS) {
            Address a = toAddr(spot);
            println("");
            println(String.format("=== 0x%08X ===", spot));

            Instruction exact = getInstructionAt(a);
            Instruction cont  = getInstructionContaining(a);
            Data data         = getDataContaining(a);
            Function f        = getFunctionContaining(a);

            println("  инструкция ровно по адресу : " + (exact != null ? exact.toString() : "НЕТ"));
            println("  адрес внутри инструкции    : " + (cont != null
                    ? cont.getAddress() + "  " + cont.toString() : "НЕТ"));
            println("  определённые данные        : " + (data != null
                    ? data.getAddress() + "  " + data.getDataType().getName() : "НЕТ"));
            println("  внутри функции             : " + (f != null
                    ? f.getName() + " @" + f.getEntryPoint() : "НЕТ"));

            if (cont != null && !cont.getAddress().equals(a)) {
                println("  >>> АДРЕС НЕ НА ГРАНИЦЕ ИНСТРУКЦИИ: он внутри команды, начинающейся с "
                        + cont.getAddress() + " => 'bra' там мнимый");
            }

            println("  --- ссылки НА этот адрес и на 16 байт вокруг ---");
            int refs = 0;
            for (long d = -16; d <= 16; d += 2) {
                Address t = toAddr(spot + d);
                for (ghidra.program.model.symbol.Reference r
                        : currentProgram.getReferenceManager().getReferencesTo(t)) {
                    println(String.format("    на %s  из %s  тип=%s", t, r.getFromAddress(),
                            r.getReferenceType()));
                    refs++;
                }
            }
            if (refs == 0) println("    (НИ ОДНОЙ — адрес недостижим по ссылкам)");

            println("  --- листинг вокруг ---");
            Address s = a.subtract(12);
            for (int i = 0; i < 10; i++) {
                CodeUnit cu = currentProgram.getListing().getCodeUnitAt(s);
                if (cu == null) { s = s.add(2); continue; }
                String mark = cu.getAddress().equals(a) ? "  <== ЗДЕСЬ" : "";
                println(String.format("    %s  %-32s%s", cu.getAddress(), cu.toString(), mark));
                s = s.add(cu.getLength());
                if (s.getOffset() > a.getOffset() + 16) break;
            }
        }
        println("");
        println("################ конец ################");
    }
}
