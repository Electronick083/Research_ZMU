#!/usr/bin/env python3
"""Уровень C пайплайна целостности ZMU: сверка BZIP2-CRC блоков ПЗУ.

Прибор хранит контрольные суммы блоков ПЗУ в config-чипе AT28C256 #1 и сверяет
их при старте (верификатор @0x20023E96, CRC-движок @0x2000147C). Скрипт повторяет
эту проверку на дампах.

Раскладка поля в 24-байтной записи дескриптора:
    start     = [rec+0x08]   (адрес в адресном пространстве MC68030)
    end       = [rec+0x0C]   (ВКЛЮЧИТЕЛЬНО)
    storedCRC = [rec+0x14]   (CRC-32/BZIP2 над rom[start..end])

Маппинг адрес -> офсет в собранном образе:
    bank B  0x200xxxxx -> addr - 0x20000000
    bank A  0x300xxxxx -> (addr - 0x30000000) + 0x40000

Запуск:
    python check_rom_crc.py <config.bin> <image.bin>
    python check_rom_crc.py 285W0027-1/Dump_D00077_OK/at28c256_1.bin image_BA.bin
"""
import sys, os, struct

# Офсеты записей дескриптора в config-чипе (подтверждены на D00077/D00109).
REC_A = [0x1D00, 0x1DD2, 0x1DEA, 0x1E02, 0x1E1A, 0x1E32, 0x1E4A, 0x1E62]
REC_B = [0x3F08, 0x3F2E, 0x3F46, 0x3F5E, 0x3F76]

BANKS = ((0x20000000, 0x00000, "B"), (0x30000000, 0x40000, "A"))
BANK_SIZE = 0x40000


def crc32_bzip2(data: bytes) -> int:
    """CRC-32/BZIP2: poly 0x04C11DB7, init 0xFFFFFFFF, не reflected, xorout 0xFFFFFFFF."""
    c = 0xFFFFFFFF
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    return c ^ 0xFFFFFFFF


def load(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def to_offset(addr: int):
    """Адрес MC68030 -> офсет в образе. None, если адрес вне окон ПЗУ."""
    for base, off, _ in BANKS:
        if base <= addr < base + BANK_SIZE:
            return addr - base + off
    return None


def bank_of(addr: int):
    for base, _, name in BANKS:
        if base <= addr < base + BANK_SIZE:
            return name
    return "?"


def read_rec(cfg: bytes, rec: int):
    """Поля блока из записи. None, если запись не помещается в чип."""
    if rec + 0x18 > len(cfg):
        return None
    start, end, crc = (struct.unpack_from(">I", cfg, rec + 0x08)[0],
                       struct.unpack_from(">I", cfg, rec + 0x0C)[0],
                       struct.unpack_from(">I", cfg, rec + 0x14)[0])
    return start, end, crc


def check_block(img: bytes, start: int, end: int, stored: int):
    """Возвращает (статус, длина, actual_crc). Статус: PASS / FAIL / SKIP-<причина>."""
    s, e = to_offset(start), to_offset(end)
    if s is None or e is None:
        return "SKIP-адрес вне ПЗУ", 0, None
    if e < s:
        return "SKIP-end<start", 0, None
    if e + 1 > len(img):
        return "SKIP-за границей образа", 0, None
    blk = img[s:e + 1]
    actual = crc32_bzip2(blk)
    return ("PASS" if actual == stored else "FAIL"), len(blk), actual


def run(cfg_path: str, img_path: str) -> int:
    cfg, img = load(cfg_path), load(img_path)
    print(f"config: {cfg_path} ({len(cfg)} байт)")
    print(f"образ : {img_path} ({len(img)} байт)")
    if len(img) != 2 * BANK_SIZE:
        print(f"  ВНИМАНИЕ: ожидался образ {2*BANK_SIZE} байт")

    npass = nfail = nskip = 0

    # Карта памяти внутри записи A: эталон @0x1D24, покрытие 0x1D2A..0x1D9F.
    # Границы взяты не на глаз — так их задаёт сам код: lea (0x2a,A4),A0 / lea (0x9f,A4),A2
    # с последующей сверкой против (0x24,A4) @0x000017FC.
    mm_stored = int.from_bytes(cfg[0x1D24:0x1D28], "big")
    mm_calc = crc32_bzip2(cfg[0x1D2A:0x1DA0])
    mm_ok = mm_stored == mm_calc
    print("\n--- карта памяти (config-чип, 0x1D2A..0x1D9F) ---")
    print(f"  stored=0x{mm_stored:08X} calc=0x{mm_calc:08X}  [{'PASS' if mm_ok else 'FAIL'}]")
    npass += mm_ok
    nfail += not mm_ok

    for label, recs in (("запись A", REC_A), ("копия @0x3F08", REC_B)):
        print(f"\n--- {label} ---")
        if label != "запись A":
            print("  (Это УСТАРЕВШАЯ КОПИЯ цепочки записи A, которую прибор НЕ ЧИТАЕТ —")
            print("   доказано 2026-07-20 через Ghidra. Правило КС то же самое (BZIP2).")
            print("   Значения справочные, в итог НЕ идут. Расхождение здесь НЕ дефект:")
            print("   у D00077/D00636 копия описывает предыдущую сборку софта.)")
        for rec in recs:
            fields = read_rec(cfg, rec)
            if fields is None:
                print(f"  @0x{rec:04X}: запись вне чипа")
                continue
            start, end, stored = fields
            status, length, actual = check_block(img, start, end, stored)
            line = (f"  @0x{rec:04X}: банк {bank_of(start)} "
                    f"0x{start:08X}..0x{end:08X}")
            if status.startswith("SKIP"):
                nskip += 1
                print(f"{line}  [{status}]")
            elif label != "запись A":
                # Копия не читается прибором — вердикт не выносим, только числа.
                print(f"{line} ({length:6d} б)  "
                      f"stored=0x{stored:08X} по правилу A=0x{actual:08X}  [справочно]")
            else:
                npass += status == "PASS"
                nfail += status == "FAIL"
                print(f"{line} ({length:6d} б)  "
                      f"stored=0x{stored:08X} actual=0x{actual:08X}  {status}")

    print(f"\nИТОГО по записи A: PASS {npass}, FAIL {nfail}, пропущено {nskip}")
    if nfail:
        print("FAIL => содержимое ПЗУ не соответствует эталону из config-чипа "
              "(детерминированная порча ячеек либо другая прошивка).")
    else:
        print("Порчи в покрытых блоках нет. ВНИМАНИЕ: блоки записи A покрывают "
              "465546 из 524288 байт = 88.8%; остальные 11.2% не проверены ничем.")
    return 1 if nfail else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        if not os.path.exists(p):
            sys.exit(f"не найден: {p}")
    sys.exit(run(sys.argv[1], sys.argv[2]))
