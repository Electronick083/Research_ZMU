//Кто вызывает CRC-движок и аддитивный движок, и что им подаётся.
//Заготовлено для задачи: проверяет ли прибор self-CRC записей дескриптора (поле +0x00).
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ZmuCrcCallers extends GhidraScript {

    // Движки из прошлых сессий (нумерация прошивки -021).
    private static final long[] ENGINES = {
        0x2000147CL,  // табличный CRC-32/BZIP2 (таблица в ОЗУ @0x400)
        0x20001154L,  // аддитивный: add.l в цикле + not.l
        0x000016DAL,  // подпрограмма сверки внутри config-чипа (вызывается из 0x17FC)
    };

    private Address a(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    private void dumpAround(Address from, int before, int after) {
        Instruction ins = getInstructionAt(from);
        if (ins == null) { println("      (нет инструкции)"); return; }
        for (int i = 0; i < before && ins.getPrevious() != null; i++) ins = ins.getPrevious();
        for (int i = 0; i < before + after && ins != null; i++) {
            String mark = ins.getAddress().equals(from) ? "  <== ВЫЗОВ" : "";
            println(String.format("      %s  %s%s", ins.getAddress(), ins.toString(), mark));
            ins = ins.getNext();
        }
    }

    @Override
    public void run() throws Exception {
        println("");
        println("######## ZmuCrcCallers: кто считает контрольные суммы ########");
        println("Задача: увидеть, подаётся ли движку payload записи дескриптора (+6..+23)");
        println("и сверяется ли результат с полем +0x00. Если да — прибор self-CRC проверяет.");

        for (long e : ENGINES) {
            Address ea = a(e);
            println("");
            println("================ движок 0x" + Long.toHexString(e) + " ================");
            Function f = getFunctionAt(ea);
            println("  функция: " + (f != null ? f.getName() : "(не распознана как функция)"));
            int n = 0;
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(ea);
            while (it.hasNext()) {
                Reference r = it.next();
                Instruction ins = getInstructionAt(r.getFromAddress());
                if (ins == null) continue;
                n++;
                Function cf = getFunctionContaining(r.getFromAddress());
                println("");
                println(String.format("  --- вызов #%d из %s (%s), тип=%s ---",
                        n, r.getFromAddress(), cf != null ? cf.getName() : "-", r.getReferenceType()));
                dumpAround(r.getFromAddress(), 12, 6);
            }
            println("");
            println("  всего вызовов: " + n);
        }

        // Кто вообще читает адреса записей цепочки 0x1DEA + 24k
        println("");
        println("================ обращения к слотам цепочки 0x1DEA..0x1E7A ================");
        for (long o = 0x1DEA; o <= 0x1E7A; o += 24) {
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a(o));
            int n = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                Instruction ins = getInstructionAt(r.getFromAddress());
                if (ins == null) continue;
                if (n == 0) println(String.format("  слот 0x%04X:", o));
                println(String.format("    из %s  %-34s %s", r.getFromAddress(), ins.toString(), r.getReferenceType()));
                n++;
            }
        }
        println("");
        println("######## конец ########");
    }
}
