#!/bin/sh
# 使い方: win-key.sh キー...   QEMU のモニタ経由でキーを送る(例: ret、meta_l-r、ctrl-alt-delete)
cd "$(dirname "$0")"
for k in "$@"; do printf 'sendkey %s\n' "$k" | nc -U -q 1 win-mon.sock >/dev/null 2>&1; done
