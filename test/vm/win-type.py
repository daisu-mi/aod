#!/usr/bin/env python3
# 使い方: win-type.py '文字列'   QEMU のモニタ経由で、US 配列として 1 文字ずつ打つ
import os, socket, sys, time
M = {' ': 'spc', '-': 'minus', '=': 'equal', '.': 'dot', ',': 'comma', '/': 'slash', ';': 'semicolon',
     "'": 'apostrophe', '\\': 'backslash', '[': 'bracket_left', ']': 'bracket_right', '`': 'grave_accent',
     '$': 'shift-4', '(': 'shift-9', ')': 'shift-0', '|': 'shift-backslash', '?': 'shift-slash',
     '{': 'shift-bracket_left', '}': 'shift-bracket_right', '_': 'shift-minus', ':': 'shift-semicolon',
     '"': 'shift-apostrophe', '>': 'shift-dot', '<': 'shift-comma', '*': 'shift-8', '&': 'shift-7',
     '%': 'shift-5', '@': 'shift-2', '!': 'shift-1', '+': 'shift-equal', '#': 'shift-3'}
s = socket.socket(socket.AF_UNIX); s.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'win-mon.sock'))
time.sleep(0.2); s.recv(65536)
for ch in sys.argv[1]:
    k = M.get(ch) or (ch if ch.islower() or ch.isdigit() else 'shift-' + ch.lower() if ch.isupper() else None)
    if k is None: sys.exit('no key for %r' % ch)
    s.sendall(('sendkey %s\n' % k).encode()); time.sleep(0.06)
    try: s.recv(65536)
    except Exception: pass
