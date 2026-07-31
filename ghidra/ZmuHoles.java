//Доказательство: обращается ли живой код в непокрытые CRC "дыры" ПЗУ.
//Четыре независимых метода: ссылки, функции+вызывающие, охват инструкций, таблицы векторов.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.List;

public class ZmuHoles extends GhidraScript {

    // Дыры CRC-покрытия. Первые три — банк B (@0x20000000), четвёртая — банк A (@0x30000000).
    private static final long[][] HOLES = {
        {0x20029770L, 0x200347FFL},   // офс образа 0x29770..0x347FF (45200 б)
        {0x2003E6F0L, 0x2003F7FFL},   // офс 0x3E6F0..0x3F7FF (4368 б)
        {0x2003FE80L, 0x2003FFFFL},   // офс 0x3FE80..0x3FFFF (384 б)
        {0x3003DDAAL, 0x3003FFFFL},   // офс 0x7DDAA..0x7FFFF (8790 б)
    };

    private int holeOf(long v) {
        for (int i = 0; i < HOLES.length; i++)
            if (v >= HOLES[i][0] && v <= HOLES[i][1]) return i;
        return -1;
    }

    private String hname(int i) {
        return String.format("дыра%d [0x%08X..0x%08X]", i + 1, HOLES[i][0], HOLES[i][1]);
    }

    @Override
    public void run() throws Exception {
        println("");
        println("################ ZmuHoles ################");
        for (int i = 0; i < HOLES.length; i++) println("  " + hname(i));
        println("");

        // ---------- МЕТОД 1: все ссылки, ведущие в дыры ----------
        println("=== МЕТОД 1: ссылки (Ghidra ReferenceManager) ===");
        ReferenceManager rm = currentProgram.getReferenceManager();
        AddressIterator srcIter = rm.getReferenceSourceIterator(
                currentProgram.getMemory(), true);
        int[] fromOutside = new int[HOLES.length];
        int[] fromInside = new int[HOLES.length];
        List<String> outsideLines = new ArrayList<>();
        while (srcIter.hasNext()) {
            Address src = srcIter.next();
            for (Reference r : rm.getReferencesFrom(src)) {
                Address to = r.getToAddress();
                int h = holeOf(to.getOffset());
                if (h < 0) continue;
                boolean srcInHole = holeOf(src.getOffset()) >= 0;
                if (srcInHole) {
                    fromInside[h]++;
                } else {
                    fromOutside[h]++;
                    Function f = getFunctionContaining(src);
                    Instruction ins = getInstructionAt(src);
                    outsideLines.add(String.format(
                            "    -> %s  ИЗ %s  тип=%s  функция=%s  инстр=%s",
                            to, src, r.getReferenceType(),
                            f != null ? f.getName() : "-",
                            ins != null ? ins.toString() : "(данные)"));
                }
            }
        }
        for (int i = 0; i < HOLES.length; i++)
            println(String.format("  %s: ИЗВНЕ %d, изнутри %d",
                    hname(i), fromOutside[i], fromInside[i]));
        println("");
        println("  --- все ссылки ИЗВНЕ (это и есть искомое) ---");
        if (outsideLines.isEmpty()) println("    (НЕТ НИ ОДНОЙ)");
        for (String s : outsideLines) println(s);
        println("");

        // ---------- МЕТОД 2: функции внутри дыр и кто их зовёт ----------
        println("=== МЕТОД 2: функции внутри дыр и их вызывающие ===");
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int inHoleFuncs = 0, calledFromOutside = 0;
        while (fit.hasNext()) {
            Function f = fit.next();
            int h = holeOf(f.getEntryPoint().getOffset());
            if (h < 0) continue;
            inHoleFuncs++;
            int outCallers = 0;
            StringBuilder who = new StringBuilder();
            for (Function c : f.getCallingFunctions(monitor)) {
                if (holeOf(c.getEntryPoint().getOffset()) < 0) {
                    outCallers++;
                    who.append(" ").append(c.getName()).append("@").append(c.getEntryPoint());
                }
            }
            if (outCallers > 0) {
                calledFromOutside++;
                println(String.format("    %s @%s <- ВЫЗЫВАЕТСЯ ИЗВНЕ:%s",
                        f.getName(), f.getEntryPoint(), who));
            }
        }
        println(String.format("  функций с точкой входа в дырах: %d", inHoleFuncs));
        println(String.format("  из них вызываемых ИЗВНЕ дыр:    %d", calledFromOutside));
        if (calledFromOutside == 0) println("    (ни одной — острова замкнуты)");
        println("");

        // ---------- МЕТОД 3: сколько инструкций Ghidra вообще нашла в дырах ----------
        println("=== МЕТОД 3: охват дизассемблера внутри дыр ===");
        int[] insCount = new int[HOLES.length];
        InstructionIterator iit = currentProgram.getListing().getInstructions(true);
        while (iit.hasNext()) {
            Instruction ins = iit.next();
            int h = holeOf(ins.getAddress().getOffset());
            if (h >= 0) insCount[h]++;
        }
        for (int i = 0; i < HOLES.length; i++) {
            long size = HOLES[i][1] - HOLES[i][0] + 1;
            println(String.format("  %s: инструкций %d (размер %d б)", hname(i), insCount[i], size));
        }
        println("  ПРИМЕЧАНИЕ: инструкции внутри дыры сами по себе НЕ означают достижимость —");
        println("  Ghidra дизассемблирует и по потоку от найденных ссылок, и эвристикой.");
        println("");

        // ---------- МЕТОД 4: таблицы векторов ----------
        println("=== МЕТОД 4: таблицы векторов ===");
        checkVectors("boot @0x20000000", 0x20000000L, 256);
        checkVectors("app  @0x20034800", 0x20034800L, 256);
        println("");
        println("################ конец ################");
    }

    private void checkVectors(String name, long base, int count) throws Exception {
        int hits = 0, valid = 0;
        for (int i = 0; i < count; i++) {
            Address a;
            try { a = toAddr(base + 4L * i); } catch (Exception e) { break; }
            int v;
            try { v = getInt(a); } catch (Exception e) { break; }
            long uv = ((long) v) & 0xFFFFFFFFL;
            if (uv >= 0x20000000L && uv <= 0x3003FFFFL) valid++;
            int h = holeOf(uv);
            if (h >= 0) {
                hits++;
                println(String.format("    %s вектор #%d -> 0x%08X  В ДЫРЕ %d", name, i, uv, h + 1));
            }
        }
        println(String.format("  %s: векторов в ПЗУ %d/%d, указывающих В ДЫРЫ: %d",
                name, valid, count, hits));
    }
}
