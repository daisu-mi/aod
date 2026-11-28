#!/usr/bin/env python3
"""Count, in an Nmap OS database, how fingerprints of old and current systems
number IP IDs (TI) and how predictable their initial sequence numbers are (SP).
Usage: tally.py [/usr/share/nmap/nmap-os-db]"""
import sys, collections
path = sys.argv[1] if len(sys.argv) > 1 else '/usr/share/nmap/nmap-os-db'
ents = []; cur = None
for l in open(path, errors='replace'):
    l = l.rstrip('\n')
    if l.startswith('Fingerprint '):
        cur = {'cls': [], 'seq': None}; ents.append(cur)
    elif cur and l.startswith('Class '):
        cur['cls'].append([x.strip() for x in l[6:].split('|')])
    elif cur and l.startswith('SEQ('):
        cur['seq'] = dict(kv.split('=', 1) for kv in l[4:-1].split('%') if '=' in kv)
def upper(v):
    hi = []
    for part in v.split('|'):
        try: hi.append(int(part.split('-')[-1], 16))
        except ValueError: pass
    return max(hi) if hi else None
groups = [('Microsoft', 'Windows', ('95', '98', 'Me')), ('Microsoft', 'Windows', ('NT',)),
          ('Microsoft', 'Windows', ('2000',)), ('Microsoft', 'Windows', ('XP',)),
          ('Microsoft', 'Windows', ('7',)),
          ('Microsoft', 'Windows', ('10', '11', '2016', '2019', '2022')),
          ('Linux', 'Linux', ('2.0.X', '2.2.X')), ('Linux', 'Linux', ('5.X', '6.X')),
          ('FreeBSD', 'FreeBSD', ('4.X',)), ('FreeBSD', 'FreeBSD', ('12.X', '13.X', '14.X'))]
print(len(ents), 'fingerprints in', path)
for v, f, gens in groups:
    sel = [e for e in ents if e['seq'] and any(c[0] == v and c[1] == f and len(c) > 2 and c[2] in gens for c in e['cls'])]
    ti = collections.Counter(e['seq'].get('TI', '(none)') for e in sel)
    ups = [u for u in (upper(e['seq']['SP']) for e in sel if 'SP' in e['seq']) if u is not None]
    print(f"{f} {'/'.join(gens)}: {len(sel)} fingerprints; TI {dict(ti)}; SP upper bound below 0x80 in {sum(u < 0x80 for u in ups)} of {len(ups)}")
