#!/usr/bin/env python3
"""ДОПОЛНИТЕЛЬНЫЙ разбор config-чипа AT28C256 #1 — структурный обход цепочки.

⚠️ ЭТО НЕ ЗАМЕНА check_rom_crc.py. Основной инструмент уровня C — check_rom_crc.py,
   и начинать всегда с него. Этот скрипт нужен, КОГДА ОСНОВНОЙ НЕ СРАБОТАЛ:

   - check_rom_crc.py не нашёл записей или нашёл не все;
   - блок неизвестной комплектации (методика гонялась только на -1 и -101);
   - результат основного скрипта выглядит бессмысленно (адреса вне ПЗУ, end < start),
     то есть похоже, что он разбирает не записи, а то, что лежит на их месте.

ЗАЧЕМ. check_rom_crc.py ходит по ЗАХАРДКОЖЕННОМУ списку слотов REC_A. На известных
блоках он верен, но слоты между экземплярами ПЕРЕСТАВЛЯЮТСЯ: у D00092 те же 8 записей
лежат в другом порядке, чем у D00077 (проверено 2026-07-21). На блоке с иной раскладкой
фиксированный список промахнётся. Здесь записи ищутся ПО СТРУКТУРЕ — позиция не важна.

Та же грабля уже была в SerialPatcher: v1.0 искала записи по «маркеру» B2 54 5C 51 и не
работала с комплектацией -101, потому что маркер оказался self-CRC конкретного HWPN.

⚠️ НО СТРУКТУРНЫЙ ПОИСК НЕ ЛУЧШЕ ФИКСИРОВАННОГО СПИСКА — ОН ДРУГОЙ. При СДВИГЕ БАЙТОВ
   он честно найдёт записи на новых местах и отрапортует «всё сходится»: сдвиг для него
   невидим, self-CRC переезжает вместе с записью. Захардкоженный REC_A в check_rom_crc.py
   работает РЕПЕРОМ, и убирать его нельзя — расхождение двух инструментов и есть
   единственный способ увидеть сдвиг. Поэтому гонять ОБА (порядок в SCRIPTS.md, шаги 3-4).
   Перестановка двигает записи внутри того же набора смещений; сдвиг — все на одну дельту.

РАСКЛАДКА ЗАПИСИ (24 байта):
    +0x00  self-CRC   CRC-32/BZIP2 над payload
    +0x04  заголовок  2 байта, В САМУ CRC НЕ ВХОДЯТ
    +0x06  payload    18 байт
             +0x00  тег (2 байта)
             +0x02  start | начало ASCII-строки
             +0x06  end
             +0x0A  доп. поле (entry и т.п.)
             +0x0E  CRC блока
Критерий записи: crc32_bzip2(b[p+6:p+24]) == b[p:p+4]. Ложные срабатывания на 32 КБ
практически исключены (шанс ~2^-32 на смещение).

Запуск:
    python walk_config.py <config.bin>                 # обход и разбор одного чипа
    python walk_config.py <config1.bin> <config2.bin>  # + сличение по полям
"""
import sys, os, struct

POLY = 0x04C11DB7

# Поля с известной раскладкой, лежащие ВНЕ записей цепочки.
# Границы взяты из кода прибора (см. ReadMe.txt), а не подобраны.
F_SERIAL_CRC = 0x1D18   # CRC-32/BZIP2 над серийником
F_SERIAL_SUM = 0x1D1D   # байт-контроль: sum(ASCII) & 0xFF
F_SERIAL     = 0x1D1E   # 6 ASCII
F_SERIAL_END = 0x1D23
F_MAP_CRC    = 0x1D24   # эталон CRC карты памяти
F_MAP_LO     = 0x1D2A   # покрытие карты памяти
F_MAP_HI     = 0x1D9F
F_UNKNOWN    = 0x1DA0   # 4-байтовое поле, назначение НЕИЗВЕСТНО

# @0x1DA0 определяется парой «комплектация + версия ПО», а НЕ экземпляром
# (проверено 2026-07-21 на шести блоках; прежний вывод «поэкземплярное» опровергнут
# прогоном на -101, где три разных блока несут одно значение).
F_UNKNOWN_BY_CONFIG = {
    0x289F7C77: "285W0027-101 / 2374-BCE-021-02  (D00636, D00650, D00669)",
    0x0C28D8E1: "285W0027-1   / 2374-BCE-021-02  (D00077)",
    0x96F8A22E: "285W0027-1   / 237E-BCE-018-02  (D00109)",
}

ROM_WINDOWS = ((0x20000000, "банк B"), (0x30000000, "банк A"))
BANK_SIZE = 0x40000


def _mktable():
    t = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ POLY) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        t.append(c)
    return t


_TABLE = _mktable()


def crc32_bzip2(data: bytes) -> int:
    c = 0xFFFFFFFF
    for b in data:
        c = ((c << 8) ^ _TABLE[((c >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
    return c ^ 0xFFFFFFFF


def load(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def find_records(cfg: bytes):
    """Все смещения, где self-CRC сходится. Позиция значения не имеет."""
    out = []
    for p in range(0, len(cfg) - 24 + 1, 2):
        stored = struct.unpack_from(">I", cfg, p)[0]
        if stored == 0:
            continue                      # нулевая запись — не запись
        if crc32_bzip2(cfg[p + 6:p + 24]) == stored:
            out.append(p)
    return out


def printable(payload: bytes) -> bool:
    """Похож ли хвост payload на ASCII-строку (эвристика, не доказательство)."""
    tail = payload[2:]
    good = sum(1 for c in tail if 32 <= c < 127 or c == 0)
    return good >= len(tail) - 2 and any(65 <= c < 123 for c in tail)


def addr_note(addr: int) -> str:
    for base, name in ROM_WINDOWS:
        if base <= addr < base + BANK_SIZE:
            return name
    if addr < 0x8000:
        return "config-чип"
    return "ВНЕ ИЗВЕСТНЫХ ОКОН"


def show_record(cfg: bytes, p: int):
    payload = cfg[p + 6:p + 24]
    tag = struct.unpack_from(">H", payload, 0)[0]
    hdr = struct.unpack_from(">H", cfg, p + 4)[0]
    head = f"  @0x{p:04X}  self-CRC 0x{struct.unpack_from('>I', cfg, p)[0]:08X}  " \
           f"тег 0x{tag:04X}  заголовок 0x{hdr:04X}"
    if printable(payload):
        s = payload[2:].decode("latin-1").rstrip("\x00 ")
        print(f"{head}  СТРОКА: '{s}'")
        return
    start, end, extra, crc = struct.unpack_from(">IIII", payload, 2)
    print(f"{head}  БЛОК: 0x{start:08X}..0x{end:08X} ({addr_note(start)}), "
          f"доп 0x{extra:08X}, CRC 0x{crc:08X}")
    if end < start:
        print("        ⚠️ end < start — запись не описывает корректный диапазон")


def check_fixed(cfg: bytes) -> int:
    """Известные поля вне цепочки. Возвращает число провалов."""
    bad = 0
    print("\n--- поля с известной раскладкой (вне цепочки) ---")

    sn = cfg[F_SERIAL:F_SERIAL_END + 1]
    sn_txt = sn.decode("latin-1")
    stored = struct.unpack_from(">I", cfg, F_SERIAL_CRC)[0]
    calc = crc32_bzip2(sn)
    ok_crc = stored == calc
    stored_sum, calc_sum = cfg[F_SERIAL_SUM], sum(sn) & 0xFF
    ok_sum = stored_sum == calc_sum
    bad += (not ok_crc) + (not ok_sum)
    print(f"  Serial No @0x{F_SERIAL:04X}: '{sn_txt}'")
    print(f"    CRC-32/BZIP2 @0x{F_SERIAL_CRC:04X}: stored=0x{stored:08X} "
          f"calc=0x{calc:08X}  [{'OK' if ok_crc else 'FAIL'}]")
    print(f"    байт-контроль @0x{F_SERIAL_SUM:04X}: stored=0x{stored_sum:02X} "
          f"calc=0x{calc_sum:02X}  [{'OK' if ok_sum else 'FAIL'}]")

    stored = struct.unpack_from(">I", cfg, F_MAP_CRC)[0]
    calc = crc32_bzip2(cfg[F_MAP_LO:F_MAP_HI + 1])
    ok = stored == calc
    bad += not ok
    print(f"  карта памяти 0x{F_MAP_LO:04X}..0x{F_MAP_HI:04X}: stored=0x{stored:08X} "
          f"calc=0x{calc:08X}  [{'OK' if ok else 'FAIL'}]")

    val = struct.unpack_from(">I", cfg, F_UNKNOWN)[0]
    known = F_UNKNOWN_BY_CONFIG.get(val)
    note = "ОБНУЛЕНО" if val == 0 else (f"известно: {known}" if known else "значение НЕ ИЗ ИЗВЕСТНЫХ")
    print(f"  поле @0x{F_UNKNOWN:04X}: 0x{val:08X} ({note})")
    print("    Назначение НЕИЗВЕСТНО, и не покрыто ни одной известной КС (гипотеза «CRC")
    print("    соседнего диапазона» опровергнута перебором 2026-07-21).")
    print("    НО значение НЕ поэкземплярное: оно определяется парой «комплектация +")
    print("    версия ПО». Известные значения:")
    for v, who in sorted(F_UNKNOWN_BY_CONFIG.items()):
        print(f"      0x{v:08X}  {who}")
    print("    Выборка: -101/-021 подтверждено ТРЕМЯ блоками; клетки -1 — по ОДНОМУ.")
    if val == 0:
        print("    ⚠️ ЗДЕСЬ НОЛЬ. Это не «своё значение экземпляра», а ОТСУТСТВУЮЩЕЕ —")
        print("       для своей пары (комплектация+ПО) ожидалось бы значение из списка.")
    return bad


def walk(path: str, quiet: bool = False):
    cfg = load(path)
    if not quiet:
        print(f"config: {path} ({len(cfg)} байт)")
    recs = find_records(cfg)
    if not quiet:
        print(f"\n--- цепочка: найдено записей {len(recs)} (поиск по структуре) ---")
        if not recs:
            print("  НИ ОДНОЙ записи со сходящейся self-CRC.")
            print("  Это значит либо испорченный config, либо неизвестный формат —")
            print("  а не то, что цепочка пуста. Сверять не с чем: см. ReadMe.txt,")
            print("  раздел «ЧТО МОЖНО И ЧЕГО НЕЛЬЗЯ УТВЕРЖДАТЬ».")
        for p in recs:
            show_record(cfg, p)
    return cfg, recs


def compare(pa: str, pb: str) -> int:
    a, ra = walk(pa)
    fa = check_fixed(a)
    print()
    b, rb = walk(pb)
    fb = check_fixed(b)

    print("\n=== СЛИЧЕНИЕ ===")
    if len(a) != len(b):
        print("  ⚠️ размеры чипов различаются, сличение по смещениям не проводится")
        return fa + fb

    n = sum(1 for i in range(len(a)) if a[i] != b[i])
    print(f"  различий всего: {n} байт")

    # Один и тот же payload может лежать в НЕСКОЛЬКИХ слотах (живая цепочка + копия
    # @0x3F08 несут одинаковые записи), поэтому payload -> СПИСОК позиций, не одна.
    def by_payload(cfg, recs):
        d = {}
        for p in recs:
            d.setdefault(bytes(cfg[p + 6:p + 24]), []).append(p)
        return d

    pay_a, pay_b = by_payload(a, ra), by_payload(b, rb)
    common = set(pay_a) & set(pay_b)
    print(f"\n  записей: {len(ra)} и {len(rb)}; "
          f"различных по содержимому: {len(pay_a)} и {len(pay_b)}, общих: {len(common)}")

    moved = [(k, pay_a[k], pay_b[k]) for k in common if pay_a[k] != pay_b[k]]
    if moved:
        print(f"  ЛЕЖАТ В РАЗНЫХ СЛОТАХ (содержимое то же): {len(moved)}")
        for _, xs, ys in sorted(moved, key=lambda t: t[1]):
            sx = ', '.join(f"0x{x:04X}" for x in xs)
            sy = ', '.join(f"0x{y:04X}" for y in ys)
            print(f"    [{sx}] -> [{sy}]")
        print("    Перестановка слотов — ШТАТНО. Разбирать цепочку по содержимому,")
        print("    а не по позиции: захардкоженный список слотов здесь промахнётся.")
        print("    NB: запись, встречающаяся дважды, — это живая цепочка плюс её копия.")

    for label, only, src, d in (("только в первом", set(pay_a) - set(pay_b), a, pay_a),
                                ("только во втором", set(pay_b) - set(pay_a), b, pay_b)):
        if only:
            print(f"\n  записи {label}: {len(only)}")
            for k in sorted(only, key=lambda k: d[k][0]):
                for p in d[k]:
                    show_record(src, p)

    # Различия ВНЕ записей — то, что не покрыто ни одной self-CRC.
    covered = set()
    for p in ra:
        covered.update(range(p, p + 24))
    for p in rb:
        covered.update(range(p, p + 24))
    outside = [i for i in range(len(a)) if a[i] != b[i] and i not in covered]
    print(f"\n  различий ВНЕ записей цепочки: {len(outside)} байт")
    if outside:
        runs, s, prev = [], outside[0], outside[0]
        for i in outside[1:]:
            if i - prev > 8:
                runs.append((s, prev))
                s = i
            prev = i
        runs.append((s, prev))
        for lo, hi in runs:
            print(f"    0x{lo:04X}..0x{hi:04X}: "
                  f"{' '.join(f'{a[i]:02X}' for i in range(lo, hi + 1))}  /  "
                  f"{' '.join(f'{b[i]:02X}' for i in range(lo, hi + 1))}")
        print("    ⚠️ Эти байты не покрыты self-CRC записей. Расхождение здесь")
        print("       НЕ ловится ни уровнем C, ни прибором — но и дефектом само по")
        print("       себе не является: часть таких полей поэкземплярна.")
    return fa + fb


def main(argv):
    for p in argv:
        if not os.path.exists(p):
            sys.exit(f"не найден: {p}")
    if len(argv) == 1:
        cfg, _ = walk(argv[0])
        bad = check_fixed(cfg)
    elif len(argv) == 2:
        bad = compare(argv[0], argv[1])
    else:
        sys.exit(__doc__)
    print(f"\nпровалов по известным полям: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    if not 1 <= len(sys.argv) - 1 <= 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
