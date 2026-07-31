#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZMU Serial Patcher — GUI для смены серийного номера в config-EEPROM (AT28C256) блока ZMU.

Меняет Serial No во ВСЕХ identity-записях файла и пересчитывает защитные поля каждой:
  - Serial No: 6 ASCII-байт @ (запись + 0x1E)
  - CRC32/BZIP2 Serial No: 4 байта BE @ (запись + 0x18)
  - байт-контроль = sum(ASCII Serial No) & 0xFF @ (запись + 0x1D)
Записи находятся по маркеру B2 54 5C 51 02 BF 00 02.
Поле B8 5E A9 A6 и дескриптор софта НЕ трогаются — Serial No они не покрывают.
"""
import os
import sys
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

MAGIC   = bytes.fromhex("B2545C5102BF0002")
SER_OFF = 0x1E   # Serial No относительно начала записи
SER_LEN = 6
CRC_OFF = 0x18   # CRC32/BZIP2 Serial No
CHK_OFF = 0x1D   # байт-контроль

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".zmu_serial_patcher.json")


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


def find_records(data: bytes):
    offs, i = [], data.find(MAGIC)
    while i != -1:
        ser = data[i + SER_OFF:i + SER_OFF + SER_LEN]
        if len(ser) == SER_LEN and all(0x20 <= b < 0x7f for b in ser):
            offs.append(i)
        i = data.find(MAGIC, i + 1)
    return offs


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
    def __init__(self, root):
        self.root = root
        self.data = None
        self.src_path = None
        self.cfg = load_config()
        self.last_dir = self.cfg.get("last_dir", "") or os.path.expanduser("~")

        root.title("ZMU Serial Patcher")
        root.geometry("660x470")
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
        self.report = scrolledtext.ScrolledText(root, height=12, font=("Consolas", 9),
                                                 bg="#101418", fg="#d8d8d8",
                                                 insertontime=0, wrap="none")
        self.report.pack(fill="both", expand=True, **pad)
        self._setup_readonly_copy()

        # новый Serial No
        fr2 = tk.Frame(root); fr2.pack(fill="x", **pad)
        tk.Label(fr2, text="Новый Serial No:", width=16, anchor="w").pack(side="left")
        self.new_var = tk.StringVar()
        tk.Entry(fr2, textvariable=self.new_var, font=("Consolas", 11)).pack(side="left", fill="x", expand=True)
        tk.Label(fr2, text="(6 символов)").pack(side="left", padx=4)

        # путь сохранения
        fr3 = tk.Frame(root); fr3.pack(fill="x", **pad)
        tk.Label(fr3, text="Сохранить как:", width=16, anchor="w").pack(side="left")
        self.out_var = tk.StringVar()
        tk.Entry(fr3, textvariable=self.out_var).pack(side="left", fill="x", expand=True)
        tk.Button(fr3, text="Обзор…", command=self.browse_out).pack(side="left", padx=4)

        # кнопка (обычного размера, справа — как ОК в Windows)
        fr4 = tk.Frame(root); fr4.pack(fill="x", **pad)
        tk.Button(fr4, text="Сохранить", command=self.save, width=12).pack(side="right")

        self.status = tk.Label(root, text="Выберите исходный файл.", anchor="w", fg="#555")
        self.status.pack(fill="x", **pad)

    # ---------- read-only text c копированием ----------
    def _setup_readonly_copy(self):
        t = self.report
        t.bind("<Key>", self._block_keys)
        t.bind("<Button-2>", lambda e: "break")          # средняя кнопка — без вставки
        for seq in ("<Control-c>", "<Control-C>", "<Control-Insert>", "<Control-Cyrillic_es>"):
            t.bind(seq, self._copy_sel)
        for seq in ("<Control-a>", "<Control-A>", "<Control-Cyrillic_ef>"):
            t.bind(seq, self._select_all)
        self.menu = tk.Menu(t, tearoff=0)
        self.menu.add_command(label="Копировать", command=self._copy_sel)
        self.menu.add_command(label="Копировать всё", command=self._copy_all)
        self.menu.add_separator()
        self.menu.add_command(label="Выделить всё", command=self._select_all)
        t.bind("<Button-3>", self._popup_menu)

    def _block_keys(self, event):
        ctrl = (event.state & 0x0004) != 0
        if ctrl and event.keysym.lower() in ("c", "a", "insert"):
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

    def log(self, text):
        self.report.delete("1.0", "end")
        self.report.insert("1.0", text)

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
            self.log("В файле НЕ найдено identity-записей (маркер B2 54 5C 51 02 BF 00 02).\n"
                     "Это не похоже на config-EEPROM ZMU.")
            self.status.config(text="Identity-записи не найдены.", fg="#a00")
            return
        lines = [f"Найдено identity-записей: {len(recs)}", ""]
        serials, all_ok = set(), True
        for o, ser, crc_ok, chk_ok, scrc, ccrc, schk, cchk in recs:
            sser = ser.decode("latin1")
            serials.add(sser)
            sc = f"0x{scrc:08X}"; cc = f"0x{ccrc:08X}"
            sk = f"0x{schk:02X}"; ck = f"0x{cchk:02X}"
            lines.append(f"Запись @ 0x{o:05X}:  Serial No = '{sser}'")
            lines.append(f"    {'CRC32/BZIP2:':<15}в файле {sc:<11}| расчёт {cc:<11}[{'OK' if crc_ok else 'НЕ СОВПАЛ'}]")
            lines.append(f"    {'байт-контроль:':<15}в файле {sk:<11}| расчёт {ck:<11}[{'OK' if chk_ok else 'НЕ СОВПАЛ'}]")
            lines.append("")
            all_ok = all_ok and crc_ok and chk_ok
        cur = next(iter(serials)) if len(serials) == 1 else "(записи расходятся!)"
        lines.insert(2, f"ТЕКУЩИЙ Serial No: {cur}")
        lines.insert(3, f"Валидность защиты Serial No: {'ВСЁ ВЕРНО' if all_ok else 'ЕСТЬ РАСХОЖДЕНИЯ'}")
        lines.insert(4, "")
        self.log("\n".join(lines))
        if len(serials) == 1 and not self.new_var.get():
            self.new_var.set(cur)
        if not self.out_var.get():
            base, ext = os.path.splitext(path)
            self.out_var.set(self.winpath(f"{base}_modified{ext or '.bin'}"))
        self.status.config(text="Файл загружен. Укажите новый Serial No и нажмите Сохранить.",
                           fg="#070" if all_ok else "#a60")

    # ---------- сохранение ----------
    def save(self):
        if self.data is None:
            messagebox.showwarning("Нет файла", "Сначала выберите исходный файл.")
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
        ok = all(c[2] and c[3] and c[1].decode("latin1") == new for c in chk)
        if ok:
            messagebox.showinfo("Готово",
                                f"Сохранено: {self.winpath(out_path)}\n\n"
                                f"Serial No изменён на '{new}' в {len(chk)} записях.\n"
                                f"CRC и байт-контроль пересчитаны и проверены — всё верно.")
            self.status.config(text=f"Сохранено: {self.winpath(out_path)}", fg="#070")
        else:
            messagebox.showwarning("Внимание",
                                   "Файл сохранён, но самопроверка показала расхождение. Проверьте формат файла.")


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
