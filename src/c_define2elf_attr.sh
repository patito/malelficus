#!/bin/bash

if [ "$1" == "" -o "$2" == "" ];
then
    echo "usage: ./c_define2elf_attr.sh input output"
    exit 1
fi    

cat "$1" | sed -E "s/^#define[\t ]?([A-Za-z0-9_]+).*[0-9a-z]+.*\/\*[ \t]?([A-Za-z0-9_\&\/\"\(\)\{\}\,\;\*\.\+'. -]+)[ \t]?\*\//\{\"\1\", \1, \"\2\"\},/g" > "$2"