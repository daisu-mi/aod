#!/bin/sh
# 使い方: win-screen.sh 出力.png   Windows 仮想マシンの画面を 1 枚撮る
cd "$(dirname "$0")"
ppm=$(mktemp --suffix=.ppm)
printf 'screendump %s\n' "$ppm" | nc -U -q 2 win-mon.sock >/dev/null 2>&1
python3 -c "
import sys
from PIL import Image
im=Image.open(sys.argv[1]); im.thumbnail((1280,800)); im.save(sys.argv[2])" "$ppm" "$1" && rm -f "$ppm"
