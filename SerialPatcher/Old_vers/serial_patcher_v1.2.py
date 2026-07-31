#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZMU Serial Patcher — GUI для смены серийного номера в config-EEPROM (AT28C256) блока ZMU.

Меняет Serial No во ВСЕХ identity-записях файла и пересчитывает защитные поля каждой:
  - Serial No: 6 ASCII-байт @ (запись + 0x1E)
  - CRC32/BZIP2 Serial No: 4 байта BE @ (запись + 0x18)
  - байт-контроль = sum(ASCII Serial No) & 0xFF @ (запись + 0x1D)
Поле B8 5E A9 A6 и дескриптор софта НЕ трогаются — Serial No они не покрывают.

ПОИСК ЗАПИСЕЙ (переделан 2026-07-20). Раньше записи искались по «маркеру»
B2 54 5C 51 02 BF 00 02 — но это не сигнатура формата, а склейка полей конкретной
комплектации: первые 4 байта суть self-CRC записи, которая считается от payload,
а в payload входит HWPN. У комплектации -101 (HWPN 285W0027-101) HWPN другой,
поэтому self-CRC = CE CA FF E7 и hdr = 02 E0 — старый поиск не находил НИЧЕГО.
Теперь записи ищутся ПО СТРУКТУРЕ (HWPN + сходящаяся self-CRC + валидный Serial No),
что покрывает -1, -101 и любую будущую комплектацию.

Раскладка identity-записи (24 байта) + блок Serial No сразу за ней:
  +0x00  self-CRC записи (BE)      CRC32/BZIP2 над payload +0x06..+0x17
  +0x04  hdr (2 байта)
  +0x06  count (2 байта)
  +0x08  HWPN, 15 ASCII (дополнен пробелами) + 0x00
  +0x18  CRC32/BZIP2 Serial No     \
  +0x1C  константа 0x01             > эти поля self-CRC записи НЕ покрывает
  +0x1D  байт-контроль Serial No   /
  +0x1E  Serial No, 6 ASCII        /
"""
import os
import re
import sys
import json
import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

VERSION = "1.2"

SER_OFF  = 0x1E   # Serial No относительно начала записи
SER_LEN  = 6
CRC_OFF  = 0x18   # CRC32/BZIP2 Serial No
CHK_OFF  = 0x1D   # байт-контроль
HWPN_OFF = 0x08   # HWPN относительно начала записи
HWPN_LEN = 15
REC_LEN  = 0x18   # длина самопроверяющейся части записи
PAY_BEG  = 0x06   # payload для self-CRC: +0x06 .. +0x18

# HWPN-якорь для быстрого поиска и SWPN (версия ПО) в хвостовой строковой таблице.
HWPN_RE = re.compile(rb"285W[0-9]{4}-[0-9]{1,3}")
SWPN_RE = re.compile(rb"[0-9A-Z]{4}-[A-Z]{3}-[0-9]{3}-[0-9]{2}")

# Поддерживаемые блоки — ТОЛЬКО для окна справки; поиск записей от списка НЕ зависит
# (он структурный), поэтому новый вариант HWPN подхватится и без правки этой таблицы.
# NB: комплектацию задаёт суффикс САМОГО HWPN (-1 / -101). Не путать с суффиксом SWPN
# (2374-BCE-021-02) — это номер ПРОГРАММЫ, ось независимая: у D00077 и D00636 SWPN
# одинаков при разных HWPN, а у D00077 и D00109 HWPN одинаков при разных SWPN.
SUPPORTED_UNITS = [
    ("Zone Management Unit (ZMU)", ["285W0027-1", "285W0027-101"]),
]

FONT = ("Consolas", 10)

WELCOME = ("Для изменения ZMU Serial Number выберите дамп первого чипа 32 кБ "
           "(на нём обычно наклейка).")

# Цвета журнала. Подобраны под ТЁМНЫЙ фон поля (#101418): исходный «#070» на тёмном
# практически не читается, поэтому взяты те же смыслы в светлых тонах.
# Зелёный оставлен ТОЛЬКО для разделителей — цветные фразы смотрелись пёстро.
# Обычные сообщения идут белым; цветом выделяются ЛИШЬ отклонения (warn/err).
COL_TEXT = "#d8d8d8"   # обычный текст, как основной fg поля
COL_SEP  = "#3fb950"
COL_WARN = "#d29922"
COL_ERR  = "#f85149"
SEP = "-" * 70

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".zmu_serial_patcher.json")


def enable_dpi_awareness():
    """Объявляет процесс DPI-осведомлённым и возвращает масштаб экрана (1.0 = 100%).

    Без этого Windows при масштабе >100% рисует окно как для 96 DPI и РАСТЯГИВАЕТ
    готовую картинку — текст выглядит размытым. Объявив осведомлённость, получаем
    отрисовку в реальном разрешении; шрифты и геометрию тогда надо домножить на
    масштаб самим, иначе окно станет мельче на ту же долю.
    Вызывать ДО создания корневого окна Tk.
    """
    if sys.platform != "win32":
        return 1.0
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)   # system DPI aware, Win 8.1+
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()    # запасной путь, Vista+
        except Exception:
            return 1.0
    try:
        dc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(dc, 88)  # LOGPIXELSX
        ctypes.windll.user32.ReleaseDC(0, dc)
        return (dpi / 96.0) if dpi else 1.0
    except Exception:
        return 1.0


BASE_W, BASE_H = 720, 560   # логический размер окна при масштабе 100%


def window_size(scale, screen_w, screen_h):
    """Размер окна с поправкой на масштаб и с защитой от выхода за экран.

    При большом масштабе на небольшом экране (напр. 200% на 1080p) окно
    720x560 превратилось бы в 1440x1120 и не поместилось бы по высоте —
    низ с кнопкой «Сохранить» уехал бы за край. Поэтому ограничиваем
    доступной областью, оставляя запас на заголовок окна и панель задач.
    """
    margin_w, margin_h = 40, 80
    w = min(int(BASE_W * scale), max(screen_w - margin_w, 480))
    h = min(int(BASE_H * scale), max(screen_h - margin_h, 400))
    return w, h


def resource_path(rel):
    """Путь к ресурсу для скрипта и для onefile-exe (PyInstaller _MEIPASS)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def load_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except Exception:
        pass


def crc32_bzip2(data: bytes) -> int:
    """CRC-32/BZIP2: poly 0x04C11DB7, init 0xFFFFFFFF, не reflected, xorout 0xFFFFFFFF."""
    c = 0xFFFFFFFF
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    return c ^ 0xFFFFFFFF


def check_byte(serial: bytes) -> int:
    return sum(serial) & 0xFF


def _is_record(data: bytes, o: int) -> bool:
    """Запись валидна, если сходится её self-CRC и Serial No — печатный ASCII.

    Порядок проверок важен: дешёвые отсекают почти всё, CRC считается последней —
    иначе полный перебор по 512-КБ файлу занимал бы больше минуты.
    """
    if o < 0 or o + SER_OFF + SER_LEN > len(data):
        return False
    ser = data[o + SER_OFF:o + SER_OFF + SER_LEN]
    if not all(0x20 <= b < 0x7f for b in ser):
        return False
    if data[o + HWPN_OFF + HWPN_LEN] != 0x00:          # терминатор HWPN
        return False
    if not all(0x20 <= b < 0x7f for b in data[o + HWPN_OFF:o + HWPN_OFF + HWPN_LEN]):
        return False
    stored = int.from_bytes(data[o:o + 4], "big")
    return crc32_bzip2(data[o + PAY_BEG:o + REC_LEN]) == stored


def find_records(data: bytes):
    """Ищет identity-записи ПО СТРУКТУРЕ, независимо от комплектации.

    Быстрый путь — якорь по HWPN (он лежит на фиксированном месте внутри записи).
    Если якорь не сработал (иной префикс HWPN у неизвестной комплектации),
    делается полный структурный перебор по сходимости self-CRC.
    """
    offs = [m.start() - HWPN_OFF for m in HWPN_RE.finditer(data)]
    offs = [o for o in offs if _is_record(data, o)]
    if offs:
        return offs
    return [o for o in range(0, max(0, len(data) - SER_OFF - SER_LEN)) if _is_record(data, o)]


def hwpn_at(data: bytes, o: int) -> str:
    return data[o + HWPN_OFF:o + HWPN_OFF + HWPN_LEN].decode("latin1").rstrip("\x00 ")


def swpn_for(data: bytes, o: int):
    """Версия ПО (SWPN) из хвостовой строковой таблицы, относящейся к записи @o.

    Офсет строки плавает между экземплярами, поэтому берётся первое вхождение
    ПОСЛЕ начала записи (у D00077/D00636 это +0x210, у D00109 — +0x1DA).
    """
    m = SWPN_RE.search(data, o)
    return (m.group().decode("latin1"), m.start()) if m else (None, None)


def analyze(data: bytes):
    """[(offset, serial_bytes, crc_ok, chk_ok, stored_crc, calc_crc, stored_chk, calc_chk)]"""
    recs = []
    for o in find_records(data):
        ser = data[o + SER_OFF:o + SER_OFF + SER_LEN]
        stored_crc = int.from_bytes(data[o + CRC_OFF:o + CRC_OFF + 4], "big")
        stored_chk = data[o + CHK_OFF]
        calc_crc = crc32_bzip2(ser)
        calc_chk = check_byte(ser)
        recs.append((o, ser, calc_crc == stored_crc, calc_chk == stored_chk,
                     stored_crc, calc_crc, stored_chk, calc_chk))
    return recs


def patch(data: bytes, new_serial: bytes) -> bytes:
    out = bytearray(data)
    for o in find_records(data):
        out[o + SER_OFF:o + SER_OFF + SER_LEN] = new_serial
        out[o + CRC_OFF:o + CRC_OFF + 4] = crc32_bzip2(new_serial).to_bytes(4, "big")
        out[o + CHK_OFF] = check_byte(new_serial)
    return bytes(out)


class App:
    def __init__(self, root, scale=1.0):
        self.root = root
        self.scale = scale
        self.data = None
        self.src_path = None
        self.cfg = load_config()
        self.last_dir = self.cfg.get("last_dir", "") or os.path.expanduser("~")

        root.title(f"ZMU Serial Patcher v{VERSION}")
        w, h = window_size(scale, root.winfo_screenwidth(), root.winfo_screenheight())
        root.geometry(f"{w}x{h}")
        try:
            root.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        pad = dict(padx=8, pady=4)

        # исходный файл
        fr1 = tk.Frame(root); fr1.pack(fill="x", **pad)
        tk.Label(fr1, text="Исходный файл:", width=16, anchor="w").pack(side="left")
        self.src_var = tk.StringVar()
        tk.Entry(fr1, textvariable=self.src_var).pack(side="left", fill="x", expand=True)
        tk.Button(fr1, text="Обзор…", command=self.browse_src).pack(side="left", padx=4)

        # отчёт о файле (только чтение, с копированием)
        # height=8 — это МИНИМУМ, а не рабочий размер: поле растягивается за счёт
        # expand=True. Запрашивать много строк нельзя — на маленьком экране при
        # большом масштабе журнал выдавил бы нижний ряд с кнопкой «Сохранить».
        self.report = scrolledtext.ScrolledText(root, height=8, font=FONT,
                                                 bg="#101418", fg="#d8d8d8",
                                                 insertontime=0, wrap="word")
        self.report.pack(fill="both", expand=True, **pad)
        for name, col in (("info", COL_TEXT), ("ok", COL_TEXT), ("warn", COL_WARN),
                          ("err", COL_ERR), ("sep", COL_SEP)):
            self.report.tag_config(name, foreground=col)
        self._setup_readonly_copy()

        # новый Serial No
        fr2 = tk.Frame(root); fr2.pack(fill="x", **pad)
        tk.Label(fr2, text="Новый Serial No:", width=16, anchor="w").pack(side="left")
        self.new_var = tk.StringVar()
        tk.Entry(fr2, textvariable=self.new_var, font=FONT).pack(side="left", fill="x", expand=True)
        tk.Label(fr2, text="(6 символов)").pack(side="left", padx=4)

        # путь сохранения
        fr3 = tk.Frame(root); fr3.pack(fill="x", **pad)
        tk.Label(fr3, text="Сохранить как:", width=16, anchor="w").pack(side="left")
        self.out_var = tk.StringVar()
        tk.Entry(fr3, textvariable=self.out_var).pack(side="left", fill="x", expand=True)
        tk.Button(fr3, text="Обзор…", command=self.browse_out).pack(side="left", padx=4)

        # кнопки (обычного размера, справа — как ОК в Windows)
        fr4 = tk.Frame(root); fr4.pack(fill="x", **pad)
        tk.Button(fr4, text="Сохранить", command=self.save, width=12).pack(side="right")
        tk.Button(fr4, text="?", command=self.show_help, width=3).pack(side="left")

        self.report.insert("end", "\n")   # отступ перед приветствием
        self.journal(WELCOME, "info")

    # ---------- read-only text c копированием ----------
    def _setup_readonly_copy(self):
        t = self.report
        t.bind("<Key>", self._block_keys)
        t.bind("<Button-2>", lambda e: "break")          # средняя кнопка — без вставки
        t.bind("<Control-Insert>", self._copy_sel)
        self.menu = tk.Menu(t, tearoff=0)
        self.menu.add_command(label="Копировать", command=self._copy_sel)
        self.menu.add_command(label="Копировать всё", command=self._copy_all)
        self.menu.add_separator()
        self.menu.add_command(label="Выделить всё", command=self._select_all)
        t.bind("<Button-3>", self._popup_menu)

    # Коды клавиш Windows (VK): не зависят от раскладки, поэтому Ctrl+A / Ctrl+C
    # работают и на русской, и на любой другой — в отличие от keysym, который
    # на кириллице приходит как Cyrillic_ef / Cyrillic_es.
    VK_A, VK_C = 65, 67

    def _block_keys(self, event):
        ctrl = (event.state & 0x0004) != 0
        if ctrl and event.keycode == self.VK_A:
            return self._select_all()
        if ctrl and event.keycode == self.VK_C:
            return self._copy_sel()
        if ctrl and event.keysym.lower() == "insert":
            return
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next",
                            "Shift_L", "Shift_R", "Control_L", "Control_R"):
            return
        return "break"

    def _copy_sel(self, event=None):
        try:
            s = self.report.get("sel.first", "sel.last")
        except tk.TclError:
            s = ""
        if s:
            self.root.clipboard_clear()
            self.root.clipboard_append(s)
        return "break"

    def _copy_all(self, event=None):
        s = self.report.get("1.0", "end-1c")
        if s:
            self.root.clipboard_clear()
            self.root.clipboard_append(s)
        return "break"

    def _select_all(self, event=None):
        self.report.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _popup_menu(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    # ---------- журнал ----------
    def journal(self, message, tag="info", body=None, body_tag=None):
        """Добавляет сообщение в журнал. Журнал НЕ очищается — копится за сеанс.

        Каждое сообщение закрывается зелёным разделителем, вокруг разделителя —
        по пустой строке. Отдельный отступ перед сообщением НЕ нужен: пустая
        строка после предыдущего разделителя уже отделяет записи друг от друга.
        `body` (разбор по записям) идёт под разделителем и тоже закрывается им.
        """
        self.report.insert("end", message.rstrip("\n") + "\n", tag)
        self._separator()
        if body:
            self.report.insert("end", body.rstrip("\n") + "\n", body_tag or ())
            self._separator()
        self.report.see("end")

    def _separator(self):
        """Разделитель, окружённый пустыми строками сверху и снизу."""
        self.report.insert("end", "\n")
        self.report.insert("end", SEP + "\n", "sep")
        self.report.insert("end", "\n")

    def show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Справка")
        win.transient(self.root)
        win.resizable(False, False)
        win.withdraw()          # прячем, пока не встанет по центру — иначе мигнёт в углу
        try:
            win.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass
        lines = ["Поддерживаемые блоки и их HWPN:", ""]
        for unit, hwpns in SUPPORTED_UNITS:
            lines.append(f"  {unit}")
            lines += [f"      {h}" for h in hwpns]
            lines.append("")

        # белая панель, текст внутри неё
        panel = tk.Frame(win, bg="white", relief="solid", borderwidth=1)
        panel.pack(fill="both", expand=True, padx=12, pady=12)
        tk.Label(panel, text="\n".join(lines).rstrip("\n"), justify="left", anchor="w",
                 bg="white", fg="#1a1a1a", font=FONT, padx=16, pady=14).pack(fill="both", expand=True)
        tk.Button(win, text="Закрыть", command=win.destroy, width=12).pack(pady=(0, 12))

        # По центру родительского окна. Тонкости:
        #  - размер берём ЗАПРОШЕННЫЙ: у скрытого окна winfo_width() вернёт 1;
        #  - позицию берём ВНЕШНЮЮ (winfo_x/y), а не клиентскую (winfo_rootx/y):
        #    geometry() двигает рамку, и при счёте от клиентской области окно
        #    уезжало ровно на высоту заголовка. Рамка у обоих окон одинакова,
        #    поэтому в разности размеров она сокращается.
        win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - win.winfo_reqwidth()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - win.winfo_reqheight()) // 2
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        win.deiconify()
        win.grab_set()

    # ---------- пути ----------
    @staticmethod
    def winpath(p):
        return os.path.normpath(p) if p else p

    def remember_dir(self, path):
        self.last_dir = os.path.dirname(os.path.abspath(path))
        self.cfg["last_dir"] = self.last_dir
        save_config(self.cfg)

    def browse_src(self):
        p = filedialog.askopenfilename(title="Выберите дамп config-EEPROM",
                                       initialdir=self.last_dir,
                                       filetypes=[("Дампы", "*.bin"), ("Все файлы", "*.*")])
        if p:
            self.remember_dir(p)
            self.load(p)

    def browse_out(self):
        p = filedialog.asksaveasfilename(title="Сохранить модифицированный файл как",
                                         initialdir=self.last_dir, defaultextension=".bin",
                                         filetypes=[("Дампы", "*.bin"), ("Все файлы", "*.*")])
        if p:
            self.remember_dir(p)
            self.out_var.set(self.winpath(p))

    # ---------- загрузка/анализ ----------
    def load(self, path):
        try:
            with open(path, "rb") as f:
                self.data = f.read()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл:\n{e}")
            return
        self.src_path = path
        self.src_var.set(self.winpath(path))
        recs = analyze(self.data)
        if not recs:
            self.journal(f"Открыт файл: {self.winpath(path)}", "ok",
                         body="В файле НЕ найдено identity-записей — сохранение заблокировано.\n"
                              "Искали по структуре: HWPN + сходящаяся self-CRC записи + печатный Serial No.\n"
                              "Это не похоже на config-EEPROM ZMU (AT28C256 #1).",
                         body_tag="err")
            return

        # --- шапка: HWPN, Serial No, версия ПО ---
        hwpns = {hwpn_at(self.data, o) for o, *_ in recs}
        serials = {ser.decode("latin1") for _, ser, *_ in recs}
        swpns = {}
        for o, *_ in recs:
            sw, at = swpn_for(self.data, o)
            if sw:
                swpns.setdefault(sw, []).append((o, at))

        hw = next(iter(hwpns)) if len(hwpns) == 1 else "(записи расходятся!)"
        cur = next(iter(serials)) if len(serials) == 1 else "(записи расходятся!)"

        lines = [f"{'HWPN (комплектация):':<22}{hw}"]
        if not swpns:
            lines.append(f"{'SWPN (Версия ПО):':<22}не найдена")
        elif len(swpns) == 1:
            sw = next(iter(swpns))
            lines.append(f"{'SWPN (Версия ПО):':<22}{sw}   [во всех записях одинаково]")
        else:
            lines.append(f"{'SWPN (Версия ПО):':<22}РАСХОЖДЕНИЕ между записями:")
            for sw, places in swpns.items():
                where = ", ".join(f"запись @0x{o:05X} → строка @0x{at:05X}" for o, at in places)
                lines.append(f"{'':22}{sw}  ({where})")
            lines.append(f"{'':22}NB: у исправных блоков SWPN во всех записях совпадает.")
        lines.append(f"{'Serial No:':<22}{cur}")
        lines += ["", f"Найдено identity-записей: {len(recs)}", ""]

        all_ok = True
        for o, ser, crc_ok, chk_ok, scrc, ccrc, schk, cchk in recs:
            sser = ser.decode("latin1")
            sc = f"0x{scrc:08X}"; cc = f"0x{ccrc:08X}"
            sk = f"0x{schk:02X}"; ck = f"0x{cchk:02X}"
            lines.append(f"Запись @ 0x{o:05X}:  Serial No = '{sser}'")
            lines.append(f"    {'CRC32/BZIP2:':<15}в файле {sc:<11}| расчёт {cc:<11}[{'OK' if crc_ok else 'НЕ СОВПАЛ'}]")
            lines.append(f"    {'байт-контроль:':<15}в файле {sk:<11}| расчёт {ck:<11}[{'OK' if chk_ok else 'НЕ СОВПАЛ'}]")
            lines.append("")
            all_ok = all_ok and crc_ok and chk_ok
        lines.insert(3, f"{'Защита Serial No:':<22}{'ВСЁ ВЕРНО' if all_ok else 'ЕСТЬ РАСХОЖДЕНИЯ'}")
        self.journal(f"Открыт файл: {self.winpath(path)}", "ok", body="\n".join(lines))
        if len(serials) == 1 and not self.new_var.get():
            self.new_var.set(cur)
        if not self.out_var.get():
            base, ext = os.path.splitext(path)
            self.out_var.set(self.winpath(f"{base}_modified{ext or '.bin'}"))
        self.journal("Файл загружен. Укажите новый Serial No и нажмите Сохранить.",
                     "ok" if all_ok else "warn")

    # ---------- сохранение ----------
    def save(self):
        if self.data is None:
            messagebox.showwarning("Нет файла", "Сначала выберите исходный файл.")
            return
        if not find_records(self.data):
            messagebox.showerror(
                "Записи не найдены",
                "В файле нет identity-записей — менять нечего.\n\n"
                "Сохранение отменено: иначе на выходе получилась бы точная копия\n"
                "исходного файла со СТАРЫМ Serial No.")
            return
        new = self.new_var.get()
        nb = new.encode("latin1", errors="replace")
        if len(nb) != SER_LEN:
            messagebox.showerror("Неверный Serial No",
                                 f"Serial No должен быть ровно {SER_LEN} символов (сейчас {len(nb)}).")
            return
        if not all(0x20 <= b < 0x7f for b in nb):
            messagebox.showerror("Неверный Serial No", "Допустимы только печатные ASCII-символы.")
            return
        out_path = self.out_var.get().strip()
        if not out_path:
            messagebox.showwarning("Нет пути", "Укажите, куда сохранить файл.")
            return
        if os.path.abspath(out_path) == os.path.abspath(self.src_path or ""):
            if not messagebox.askyesno("Перезапись",
                                       "Путь совпадает с исходным файлом. Перезаписать оригинал?"):
                return
        try:
            patched = patch(self.data, nb)
            with open(out_path, "wb") as f:
                f.write(patched)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить:\n{e}")
            return
        self.remember_dir(out_path)
        chk = analyze(patched)
        # len(chk) обязателен: на пустом списке all(...) вернул бы True и отрапортовал
        # успех при нуле изменённых записей.
        ok = bool(chk) and all(c[2] and c[3] and c[1].decode("latin1") == new for c in chk)
        if ok:
            self.journal(f"Записан Serial No '{new}' в {len(chk)} записях.\n"
                         f"Файл: {self.winpath(out_path)}\n"
                         f"CRC и байт-контроль пересчитаны и проверены — всё верно.", "ok")
            # Подробности (число записей, сверка CRC) не дублируем — они в журнале.
            messagebox.showinfo("Готово",
                                f"Сохранено: {self.winpath(out_path)}\n\n"
                                f"Serial No изменён на '{new}'.")
        else:
            self.journal(f"Файл сохранён: {self.winpath(out_path)}\n"
                         f"НО самопроверка показала расхождение — проверьте формат файла.", "err")
            messagebox.showwarning("Внимание",
                                   "Файл сохранён, но самопроверка показала расхождение. Проверьте формат файла.")


if __name__ == "__main__":
    scale = enable_dpi_awareness()          # обязательно ДО создания Tk()
    root = tk.Tk()
    # Tk переводит размер шрифта в точках в пиксели через scaling (пикселей на точку).
    # При 96 DPI это 96/72; домножаем на масштаб экрана, иначе текст выйдет мельче.
    root.tk.call("tk", "scaling", scale * 96.0 / 72.0)
    App(root, scale)
    root.mainloop()
