#!/usr/bin/env python3
"""
Проверка целостности дампа одной параллельной EEPROM (X28C16/64/256/512 и т.п.).
Размер чипа и число адресных линий определяются автоматически по длине файла.

Ищет признаки обрыва/залипания пинов:
  - адресной шины  -> циклические повторы (период = степень двойки);
  - шины данных    -> зафиксированный бит во всём файле.
А также ЗАМЫКАНИЯ между линиями (детерминированы, не ловятся сравнением двух чтений):
  - линий данных   -> пара бит всегда равна/противоположна, либо асимметрия D_i=1 ⇒ D_j=1;
  - адресных линий -> дамп инвариантен к обмену пары адресных бит;
  - аномалия числа уникальных байт-значений при высокой энтропии.

Использование:
    python check_dump.py chip1.bin                # анализ одного дампа
    python check_dump.py chip1.bin chip1_re.bin   # + сравнение двух чтений
"""
import sys
import math
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

DATA_BITS = 8             # I/O0..I/O7

# Известные параллельные EEPROM (байт -> имя)
KNOWN = {
    2048:   "X28C16  (16 Кбит, 2K x8, A0-A10)",
    8192:   "X28C64  (64 Кбит, 8K x8, A0-A12)",
    32768:  "X28C256 (256 Кбит, 32K x8, A0-A14)",
    65536:  "X28C512 (512 Кбит, 64K x8, A0-A15)",
    131072: "1 Мбит (128K x8, A0-A16)",
}


def load(path):
    with open(path, "rb") as f:
        return f.read()


def addr_bits(n):
    """Число адресных линий = log2(размер). Возвращает None, если не степень двойки."""
    if n <= 0 or (n & (n - 1)) != 0:
        return None
    return n.bit_length() - 1


def check_size(data):
    n = len(data)
    ab = addr_bits(n)
    print(f"[Размер] {n} байт", end="  ")
    if ab is None:
        print("!!! не степень двойки — повреждённый/обрезанный дамп или не тот чип.")
        return None
    name = KNOWN.get(n, f"{n} байт, A0-A{ab-1}")
    print(f"OK -> {name}")
    return ab


def check_data_lines(data):
    """Залипшие биты данных: OR/AND по всем байтам."""
    or_all, and_all = 0x00, 0xFF
    for b in data:
        or_all |= b
        and_all &= b
    print("\n[Линии данных] анализ битовых плоскостей I/O0..I/O7")
    suspect = []
    for bit in range(DATA_BITS):
        m = 1 << bit
        ever_1 = bool(or_all & m)
        ever_0 = not (and_all & m)
        if not ever_1:
            print(f"  D{bit}: ЗАЛИП в 0 (бит нигде не равен 1)  <-- подозрение на обрыв линии данных")
            suspect.append(bit)
        elif not ever_0:
            print(f"  D{bit}: ЗАЛИП в 1 (бит везде равен 1)      <-- подозрение на обрыв линии данных")
            suspect.append(bit)
        else:
            print(f"  D{bit}: OK (меняется)")
    return suspect


def check_address_lines(data, ab):
    """Обрыв адресной линии: toggling бита i не влияет на данные -> dump[a]==dump[a^(1<<i)]."""
    n = len(data)
    print(f"\n[Адресные линии] тест влияния битов A0..A{ab-1} (циклические повторы)")
    suspect = []
    for i in range(ab):
        step = 1 << i
        if step >= n:
            break
        mism = 0
        # сравниваем пары адресов, отличающихся только битом i
        for a in range(n):
            if a & step:        # считаем каждую пару один раз
                continue
            if data[a] != data[a ^ step]:
                mism += 1
        total = n // 2
        if mism == 0:
            print(f"  A{i:2d} (период {step:6d}): НЕ влияет на данные  <-- обрыв/залипание адресной линии")
            suspect.append(i)
        else:
            frac = 100.0 * mism / total
            tag = ""
            if frac < 1.0:
                # мягкая подсказка: низкое влияние МОЖЕТ быть обрывом, но надёжно
                # обрыв/плавающую линию различает только сравнение двух чтений (не статикой)
                tag = "  <-- влияет слабо; если это обрыв — проявится при сравнении двух чтений"
            print(f"  A{i:2d} (период {step:6d}): различий {mism}/{total} ({frac:.1f}%){tag}")
    return suspect


def check_constants(data):
    print("\n[Заполнение]")
    c = Counter(data)
    n = len(data)
    z = c.get(0x00, 0)
    f = c.get(0xFF, 0)
    print(f"  0x00: {z} ({100.0*z/n:.1f}%)   0xFF: {f} ({100.0*f/n:.1f}%)   уникальных байт-значений: {len(c)}")
    # самый длинный одинаковый прогон
    longest, run, prev = 1, 1, data[0]
    for b in data[1:]:
        if b == prev:
            run += 1
            longest = max(longest, run)
        else:
            run, prev = 1, b
    print(f"  самый длинный одинаковый прогон: {longest} байт")
    # энтропия
    ent = -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())
    print(f"  энтропия: {ent:.3f} бит/байт (8.0 = максимум; ~<1 при сильной структуре/повторах)")
    if len(c) == 1:
        print("  !!! ВЕСЬ файл одинаковый -> пустой/мёртвый чип, нет питания или нет линий данных")
    return c, ent


def check_data_shorts(data, hist):
    """Замыкания линий данных: корреляция пар бит по гистограмме значений.
    Полное равенство/противоположность = КЗ; односторонний пропуск комбинации = связь/обрыв."""
    print("\n[Замыкания линий данных] корреляция пар I/O0..I/O7")
    n = len(data)
    found = []
    for i in range(DATA_BITS):
        for j in range(i + 1, DATA_BITS):
            n01 = n10 = eq = 0
            for v, cnt in hist.items():
                bi, bj = (v >> i) & 1, (v >> j) & 1
                if bi == bj:
                    eq += cnt
                elif bi and not bj:
                    n10 += cnt
                else:
                    n01 += cnt
            eqf = eq / n
            if eqf > 0.999:
                print(f"  D{i}=D{j}: равны в {eqf*100:.2f}% байт  <-- ЗАМЫКАНИЕ (линии всегда равны)")
                found.append(f"D{i}=D{j}")
            elif eqf < 0.001:
                print(f"  D{i}≠D{j}: равны лишь в {eqf*100:.2f}%  <-- ЗАМЫКАНИЕ/инверсия (всегда противоположны)")
                found.append(f"D{i}≠D{j}")
            elif n10 == 0 and n01 > 0:
                print(f"  D{i}->D{j}: нет ни одного (D{i}=1,D{j}=0)  <-- связь/обрыв: D{i}=1 ⇒ D{j}=1")
                found.append(f"D{i}->D{j}")
            elif n01 == 0 and n10 > 0:
                print(f"  D{j}->D{i}: нет ни одного (D{i}=0,D{j}=1)  <-- связь/обрыв: D{j}=1 ⇒ D{i}=1")
                found.append(f"D{j}->D{i}")
    if not found:
        print("  норма: явных замыканий между линиями данных нет")
    return found


def check_address_shorts(data, ab):
    """Замыкание/перепутка пары адресных линий: дамп инвариантен к обмену бит i<->j
    (адреса, отличающиеся только обменом этих бит, дают одинаковый байт)."""
    n = len(data)
    print(f"\n[Замыкания адресных линий] инвариантность к обмену пар A0..A{ab-1}")
    found = []
    for i in range(ab):
        si = 1 << i
        if si >= n:
            break
        for j in range(i + 1, ab):
            sj = 1 << j
            if sj >= n:
                break
            both = si | sj
            mism = 0
            vals = set()  # разнообразие данных в проверяемой зоне
            # адреса с битом i=0, битом j=1 -> сравниваем с обменом этих бит
            for a in range(n):
                if (a & si) == 0 and (a & sj):
                    if data[a] != data[a ^ both]:
                        mism += 1
                    elif len(vals) < 8:
                        vals.add(data[a])
            # инвариантность к обмену в зоне СПЛОШНОЙ константы (нули) тривиальна и не значит КЗ
            if mism == 0 and len(vals) >= 4:
                print(f"  A{i}<->A{j}: дамп инвариантен к обмену (зона разнообразна)  <-- ЗАМЫКАНИЕ/перепутаны линии адреса")
                found.append(f"A{i}<->A{j}")
    if not found:
        print("  норма: закороченных/перепутанных адресных линий нет")
    return found


def check_value_diversity(hist, ent):
    """Аномалия разнообразия: при высокой энтропии должны встречаться почти все 256 значений.
    Существенный дефицит -> часть бит данных не варьируется независимо (замыкание/обрыв)."""
    uniq = len(hist)
    if uniq < 256 and ent > 4.0:
        print(f"\n[Разнообразие] !!! только {uniq}/256 значений при энтропии {ent:.2f} "
              f"-> часть линий данных не независима (замыкание/обрыв шины данных)")
        return True
    return False


def compare_reads(a, b):
    print("\n[Повторное чтение] сравнение двух дампов")
    if len(a) != len(b):
        print(f"  !!! разные размеры: {len(a)} vs {len(b)}")
        return
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    if not diff:
        print("  OK: оба чтения идентичны (контакт стабильный)")
    else:
        print(f"  !!! {len(diff)} различающихся байт -> ПЛАВАЮЩИЙ контакт / дрожащий пин")
        for i in diff[:8]:
            print(f"      0x{i:05X}: {a[i]:02X} != {b[i]:02X}")
        if len(diff) > 8:
            print(f"      ... ещё {len(diff)-8}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    print(f"=== {path} ===")
    data = load(path)
    ab = check_size(data)
    if not data:
        return
    ds = check_data_lines(data)
    ads = [] if ab is None else check_address_lines(data, ab)
    hist, ent = check_constants(data)
    dshort = check_data_shorts(data, hist)
    ashort = [] if ab is None else check_address_shorts(data, ab)
    div_anom = check_value_diversity(hist, ent)
    if len(sys.argv) >= 3:
        compare_reads(data, load(sys.argv[2]))
    print("\n=== ИТОГ ===")
    if ds:
        print(f"  Подозрение на линии ДАННЫХ (залип бит): {', '.join('D'+str(b) for b in ds)}")
    if ads:
        print(f"  Подозрение на АДРЕСНЫЕ линии (обрыв): {', '.join('A'+str(b) for b in ads)}")
    if dshort:
        print(f"  ЗАМЫКАНИЕ/связь линий ДАННЫХ: {', '.join(dshort)}")
    if ashort:
        print(f"  ЗАМЫКАНИЕ/перепутка АДРЕСНЫХ линий: {', '.join(ashort)}")
    if div_anom:
        print(f"  Дефицит уникальных значений -> зависимые линии данных (замыкание/обрыв шины)")
    if not (ds or ads or dshort or ashort or div_anom):
        print("  Явных обрывов/замыканий адреса/данных не обнаружено.")
    print("  Примечание: ОБРЫВ/плавающую линию надёжно ловит только сравнение двух чтений")
    print("  (python check_dump.py f_a.bin f_b.bin) — замыкания детерминированы и видны по одному файлу.")


if __name__ == "__main__":
    main()
