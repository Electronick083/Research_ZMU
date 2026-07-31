//Для КАЖДОЙ ссылки на запись A (0x1D00) печатает код обходчика цепочки:
//насколько далеко он может уйти от начала цепочки. Так проверяется, дотягивается
//ли прибор до копии @0x3F08 на КОНКРЕТНОЙ прошивке.
//@category ZMU
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ZmuWalk extends GhidraScript {

    private Address a(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    @Override
    public void run() throws Exception {
        println("");
        println("################ ZmuWalk ################");
        println("функций: " + currentProgram.getFunctionManager().getFunctionCount()
                + ", инструкций: " + currentProgram.getListing().getNumInstructions());

        int n = 0;
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a(0x1D00));
        while (it.hasNext()) {
            Reference r = it.next();
            Address from = r.getFromAddress();
            Instruction ins = getInstructionAt(from);
            if (ins == null) continue;
            n++;
            println("");
            println("===== ссылка #" + n + " на 0x1D00 из " + from + " =====");
            for (int i = 0; i < 26 && ins != null; i++) {
                println(String.format("  %s  %s", ins.getAddress(), ins.toString()));
                ins = ins.getNext();
            }
        }
        println("");
        println("ссылок-инструкций на 0x1D00: " + n);
        println("################ конец ################");
    }
}
