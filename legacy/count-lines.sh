#!/bin/sh
# Computes the size of the 2001 fingerprinting patch as far as the files kept
# in this directory allow.  Reads the files only; same method as
# legacy/count-lines.sh of the aoi repository.
#   for each patch file: files touched, lines added, lines added that are
#   not blank, lines removed, and the earliest and latest date in its
#   "+++" header lines
#   for the source tree src/: every file that has a copy named FILE.orig is
#   compared with that copy (diff -u), and the same four numbers are given
#   per file and in total.  Files of src/ without an .orig copy are not
#   compared, so changes in them (if any) are not in this total.
# usage: sh count-lines.sh > count-lines.txt     (run from any directory)
cd "$(dirname "$0")" || exit 1
for P in aod-freebsd43.patch aod.patch; do
	echo "$P: files $(grep -c '^+++ ' $P), added $(grep '^+' $P | grep -vc '^+++ '), added not blank $(grep '^+' $P | grep -v '^+++ ' | grep -vc '^+[[:space:]]*$'), removed $(grep '^-' $P | grep -vc '^--- ')"
	grep '^+++ ' $P | sed 's/^+++ \([^	]*\)	/  new file date: \1  /'
done
ta=0; tn=0; tr=0; tf=0
for o in $(find src -name '*.orig' | sort); do
	f=${o%.orig}
	a=$(diff -u $o $f | grep '^+' | grep -vc '^+++ ')
	n=$(diff -u $o $f | grep '^+' | grep -v '^+++ ' | grep -vc '^+[[:space:]]*$')
	r=$(diff -u $o $f | grep '^-' | grep -vc '^--- ')
	echo "$f against $o: added $a, added not blank $n, removed $r"
	ta=$((ta+a)); tn=$((tn+n)); tr=$((tr+r)); [ $a -gt 0 -o $r -gt 0 ] && tf=$((tf+1))
done
echo "src/ against its .orig copies: files that differ $tf, added $ta, added not blank $tn, removed $tr"
