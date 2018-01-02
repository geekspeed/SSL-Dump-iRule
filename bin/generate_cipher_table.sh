#!/bin/bash
echo "Code\tCipher\tCipher Suite" > openssl-ciphers.tsv
openssl ciphers -V 'ALL:eNULL:@STRENGTH'| sed -e 's/0x//g' | sed -e 's/,//' | awk '{ print $1 "\t" $3 "\t" $4 }' >> openssl-ciphers.tsv
