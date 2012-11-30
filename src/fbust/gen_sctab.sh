#!/bin/sh

echo "[*] Indexing syscalls on your machine..."

cat /usr/include/asm/unistd.h | \
  grep '#define.*__NR_.*[0-9].*$' | \
  sed 's/__NR_//' | \
  awk '{printf "  { \"%s\", %d },\n",$2,$3}' >sctab-list.h

COUNT=$[`wc -l <sctab-list.h`]

if [ "$COUNT" -lt "32" ]; then
  echo "[-] Oops, something went wrong!"
  exit 1
else
  echo "[+] Found $COUNT syscalls."
fi

echo '  { 0, 0 }' >>sctab-list.h

exit 0

