# A count of the entries of Nmap 7.98's fingerprint database

This directory holds a count that the article "The Jail We Dismissed" mentions
in its discussion of the five settings kept from 2001 (section "The legacy
settings under a current scanner"). The text below stood in the article until
its revision of 2026-11-27 and was moved here; the article keeps one sentence.
It is a count of database entries, not a measurement of any host.

| File | What it is |
|---|---|
| `tally.py` | the counting script; reads an `nmap-os-db` file |
| `tally-nmap-7.98.txt` | its output on the file installed with Nmap 7.98 on the prober |
| `nmap-os-db.sha256.txt` | SHA-256 of that file, taken on 2026-11-27; the database itself is not stored here |

## Why it was made

None of the 25 scans of the five legacy settings reported an exact match (see
`../results/personalities-2001/`). One difference between the patch of 2001
and the rebuilt module is certain from the code: the patch chose how the
initial sequence number advanced, and the rebuilt module does not change
initial sequence numbers at all. A possible explanation of the scan result,
which was not tested, is that the scanner now weighs how sequence numbers and
IP identifiers advance, and that old systems are recognised partly by
behaviour that current stacks no longer have. The count asks only whether the
database is consistent with that.

## What was counted

The entries of the fingerprint file (6,036 in all) were grouped by the vendor,
family and generation given in their class lines, and two fields of the
sequence test were read:

- `TI`, the class of IP identifier sequence in TCP replies. The script counts
  the literal value of the field, so `TI=I` (incrementing), `TI=Z` (zero),
  `TI=RD`, `TI=BI` and so on are separate bins, and so are mixed values such
  as `I|RD` or `BI|RI`: an entry with `TI=I|RD` is counted under `I|RD`, not
  under `I`. Entries without the field are counted as `(none)`.
- `SP`, the index of how hard the initial sequence number is to predict. For
  each entry the upper end of the range it allows was taken, and the question
  was whether that upper end lies below hexadecimal 80. An entry without a
  usable `SP` value is left out of that count. The threshold is ours.

## What it gives

By this count, 13 of the 14 entries for Linux 2.0 and 2.2 and 14 of the 19 for
FreeBSD 4 have `TI=I`, while 60 of 63 for Linux 5 and 6 and 20 of 23 for
FreeBSD 12 to 14 have `TI=Z`. Of the 96 entries for Windows 10, 11 and the
servers from 2016, 89 still have `TI=I` (six more have the mixed value `I|RD`
and one `RD`). For the sequence number, the upper end of `SP` lies below the
threshold in 30 of the 34 entries for Windows 95, 98 and Me and in 12 of the
24 entries for Windows NT that have the value (27 entries in all), against 1
of the 97 for Windows 2000 and none of the 96 for Windows 10, 11 and the
servers.

For the Windows 2000 setting the count therefore explains nothing: by either
field its entries look like those of current Windows (89 of the 97 have
`TI=I`). The tally also has rows for Windows XP and Windows 7, which the
article does not use.

## Limits

These are counts of database entries; the entries are not a sample of
operating systems. The file counted is the one installed with Nmap 7.98 on the
prober (package `nmap-common`, version 7.98+dfsg-1). The stored scan outputs
name the Nmap version and not the database file that was loaded, so that the
scans used this file rests on the installed package and on nothing recorded
with the scans.
