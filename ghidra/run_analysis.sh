#!/usr/bin/env bash
# Разбор ПЗУ ZMU в Ghidra headless.
#   ./run_analysis.sh <image.bin> <config.bin> [ScriptName.java ...]
# Пример (D00077):
#   ./run_analysis.sh ../image_BA.bin ../Dump_D00077_OK/at28c256_1.bin ZmuRefs2.java
#
# Что делает: режет образ на банки, кладёт их в work/, импортирует банк B по
# адресу 0x20000000, преСкриптом ZmuMap.java достраивает карту памяти
# (банк A @0x30000000, config-чип @0x00000000, ОЗУ, I/O), гоняет автоанализ,
# затем запускает указанные скрипты.
set -euo pipefail

GHIDRA="${GHIDRA:-C:/Tools/ghidra_12.1.2_PUBLIC}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/work"

IMAGE="${1:?укажите образ ПЗУ, напр. ../image_BA.bin}"
CONFIG="${2:?укажите config-чип, напр. ../Dump_D00077_OK/at28c256_1.bin}"
shift 2
SCRIPTS=("$@")
[ ${#SCRIPTS[@]} -eq 0 ] && SCRIPTS=(ZmuRefs2.java)

mkdir -p "$WORK"
python - "$IMAGE" "$CONFIG" "$WORK" <<'PY'
import sys, shutil
img, cfg, work = sys.argv[1], sys.argv[2], sys.argv[3]
d = open(img, 'rb').read()
assert len(d) == 0x80000, f"ожидался образ 512 КБ, получено {len(d)}"
open(f"{work}/bankB.bin", 'wb').write(d[:0x40000])   # ПЗУ @0x20000000
open(f"{work}/bankA.bin", 'wb').write(d[0x40000:])   # ПЗУ @0x30000000
shutil.copyfile(cfg, f"{work}/config.bin")
print(f"work/: bankB.bin, bankA.bin, config.bin ({img})")
PY

rm -rf "$WORK/proj"; mkdir -p "$WORK/proj"
POST=()
for s in "${SCRIPTS[@]}"; do POST+=(-postScript "$s"); done

"$GHIDRA/support/analyzeHeadless.bat" "$(cygpath -w "$WORK/proj")" ZMU \
  -import "$(cygpath -w "$WORK/bankB.bin")" \
  -processor 68000:BE:32:MC68030 \
  -loader BinaryLoader -loader-baseAddr 0x20000000 \
  -scriptPath "$(cygpath -w "$HERE")" \
  -preScript ZmuMap.java "${POST[@]}"

# Повторный прогон скриптов без анализа (проект сохранён):
#   "$GHIDRA/support/analyzeHeadless.bat" work/proj ZMU -process bankB.bin \
#       -noanalysis -scriptPath . -postScript ZmuDump.java
