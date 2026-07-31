#!/usr/bin/env python3
"""Сборка цельного 32-битного образа массива 8x X28C512 из 8 эталонных дампов.

Распиновка (УТОЧНЕНА по структуре собранного образа, 2026-06-09):
  байтовые лейны: byte0=chip1/2 (LSB), byte1=chip3/4, byte2=chip7/8, byte3=chip5/6 (MSB)
  (лейны чипов 5,6 и 7,8 поменяны местами относительно первоначальной схемы — байт2<->байт3)
  банк A (CE 1,3,5,7): слово(byte0..3) = chip1, chip3, chip7, chip5
  банк B (CE 2,4,6,8): слово(byte0..3) = chip2, chip4, chip8, chip6
  Раскладка банков = ДВЕ ПОЛОВИНЫ (банк = старший адресный бит): внутри банка данные непрерывны.
  Подтверждено читаемостью текста: "COPYRIGHT 1992-2001, THE BOEING COMPANY..." (ZMU, Boeing).
"""
import sys, os, math
from collections import Counter

def load(p):
    with open(p, "rb") as f:
        return f.read()

def load_chips(src):
    """Грузит 8 чипов из папки src. Имя: '512-N_a.bin' (рабочий набор) или '512-N.bin'."""
    chips = {}
    for n in range(1, 9):
        for name in (f"512-{n}_a.bin", f"512-{n}.bin"):
            p = os.path.join(src, name)
            if os.path.exists(p):
                chips[n] = load(p); break
        else:
            sys.exit(f"не найден дамп чипа {n} в {src}")
    return chips

def bank_words(chips, N, c0, c1, c2, c3):
    """c0=байт0(LSB)..c3=байт3(MSB). Возвращает bytes длиной 4*N (little-endian слова)."""
    out = bytearray(4 * N)
    out[0::4] = chips[c0]
    out[1::4] = chips[c1]
    out[2::4] = chips[c2]
    out[3::4] = chips[c3]
    return bytes(out)

def assemble(src):
    """Собирает финальный образ (банк B в младших адресах). Возвращает (img, bankA, bankB)."""
    chips = load_chips(src)
    N = len(chips[1])
    bankA = bank_words(chips, N, 1, 3, 7, 5)  # byte0..3 = chip1,chip3,chip7,chip5
    bankB = bank_words(chips, N, 2, 4, 8, 6)  # byte0..3 = chip2,chip4,chip8,chip6
    # Раскладка — две половины. Порядок половин по вектору сброса MC68030: банк B в младших адресах.
    return bankB + bankA, bankA, bankB

def ascii_runs(data, minlen=4):
    """Считает печатные ASCII-строки длиной >= minlen."""
    runs = []
    cur = 0
    for b in data:
        if 0x20 <= b < 0x7f:
            cur += 1
        else:
            if cur >= minlen:
                runs.append(cur)
            cur = 0
    if cur >= minlen:
        runs.append(cur)
    return runs

def entropy(data):
    c = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def report(name, data):
    runs = ascii_runs(data)
    total_str_bytes = sum(runs)
    print(f"\n=== {name} ({len(data)} байт) ===")
    print(f"  энтропия: {entropy(data):.3f}")
    print(f"  ASCII-строк (>=4): {len(runs)}, всего байт в строках: {total_str_bytes} "
          f"({100.0*total_str_bytes/len(data):.2f}%), самая длинная: {max(runs) if runs else 0}")

if __name__ == "__main__":
    # argv: [src_dir] [out_file]. По умолчанию — рабочее устройство D00077.
    src = sys.argv[1] if len(sys.argv) > 1 else "285W0027-1/Dump_D00077_OK"
    out = sys.argv[2] if len(sys.argv) > 2 else "image_BA.bin"
    img, bankA, bankB = assemble(src)
    with open(out, "wb") as f: f.write(img)
    print(f"источник: {src}")
    report("bankA (chip1,3,7,5)", bankA)
    report("bankB (chip2,4,8,6)", bankB)
    report("ФИНАЛЬНЫЙ образ B|A (банк B в младших адресах)", img)
    print(f"\nСохранено: {out} (512 КБ) — банк B в младших адресах (MC68030)")
