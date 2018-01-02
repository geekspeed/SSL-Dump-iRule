#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""This module's docstring summary line.
This is a multi-line docstring. Paragraphs are separated with blank lines.
Lines conform to 79-column limit.
Module and packages names should be short, lower_case_with_underscores.
Notice that this in not PEP8-cheatsheet.py
Seriously, use flake8. Atom.io with https://atom.io/packages/linter-flake8
is awesome!
See http://www.python.org/dev/peps/pep-0008/ for more PEP-8 details
"""
import argparse
import csv
import os
import re
import sys

VERSION = "1.0a"
CIPHER_FILE = "./openssl-ciphers.tsv"
FIRST_REGEX = ' ([a-zA-z]\w+.[a-zA-Z]\w+)(\s\w+)(\s\w+)(\[.*\]\:)(.*/Common/)'
SECOND_REGEX = ' Client: '
CIPHER_REGEX = ' attempts SSL with ciphers: '
HAND_REGEX = ' successfully negotiates '
UNSUPPORTED_REGEX = '\|Client using unsupported SSL Handshake using '
BITS_REGEX = ' and '
USER_AGENT_REGEX = ' bits using the Agent '
IP_PORT_REGEX = '(?:[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})])(\:\d{1,6})\s'
COMBINED_FILE_HEADER = "Date | Virtual Server| Client Src IP | Cipher | Handshake | Failed Handshake | Bits | User Agent "
FAILURE_FILE_HEADER = "Date | Virtual Server | Client Src IP | Failed Handshake | Bits | User Agent"
HANDSHAKE_FILE_HEADER = "Date | Virtual Server | Client Src IP | Handshake"
CIPHER_FILE_HEADER = "Date | Virtual Server | Client Src IP | Cipher"
CIPHER_LOOKUP = {}
CIPHER_SUITE_LOOKUP = {}

def __write_file(file, data):
	for k, v in data.items():
		file.write(str(v)+"\n")

def __build_cipher_table():
	with open (CIPHER_FILE, 'rb') as CIPHER_REF:
		r = csv.reader(CIPHER_REF, delimiter='\t')
		for row in r:
			CIPHER_LOOKUP.update({ row[0] : row[1] })
			CIPHER_SUITE_LOOKUP.update({ row[0] : row[2] })


def __cipher_translate(data):
	data_line = data.rsplit('|',1)[0]
	data_payload = ":"
	data_store = data.rsplit('|',1)[1].upper().split(',')

	for d in data_store:
		if d in CIPHER_LOOKUP:
			if ( data_payload == ":"):
				data_payload = CIPHER_LOOKUP[d] + " (" + CIPHER_SUITE_LOOKUP[d] + ")"
			else:
				data_payload = data_payload + ", "+ CIPHER_LOOKUP[d] + " (" + CIPHER_SUITE_LOOKUP[d] + ")"
		else:
			if ( data_payload == ":"):
				data_payload = "CIPHER-NOT-FOUND-[" + d + "]"
			else:
				data_payload = data_payload + ", CIPHER-NOT-FOUND-[" + d + "]"
	data_line = data_line + '|' + data_payload
	return data_line	


def __parse_file(infile, outfile, handshakefile, cipherfile, failfile):
	logFile = {}
 	newLine = {}
 	cipherLine = {}
 	handshakeLine = {}
 	failureLine = {}

 	i = 0;
 	j = 0;
 	k = 0;
 	h = 0;
 	newLine[i] = COMBINED_FILE_HEADER
 	cipherLine[j] = CIPHER_FILE_HEADER
 	handshakeLine[k] = HANDSHAKE_FILE_HEADER
 	failureLine[h] = FAILURE_FILE_HEADER

 	lines = [l for l in infile]
 	for line in lines:
 		line = line.strip()
 		i = i+1
 		p = re.compile(FIRST_REGEX)
 		newLine[i] = p.sub('|',line)
 		p = re.compile(SECOND_REGEX)
 		newLine[i] = p.sub('|', newLine[i])
 		p = re.compile(IP_PORT_REGEX)
 		if (p.search(newLine[i])):
 			newLine[i] = p.sub('|', newLine[i])
 		p = re.compile(CIPHER_REGEX)
 		if(p.search(newLine[i])):
 			j = j+1
 			cipherLine[j] = p.sub('|',newLine[i])
 			newLine[i] = cipherLine[j]
 			newLine[i] = __cipher_translate(cipherLine[j])
 			cipherLine[j] = newLine[i]
 		p = re.compile(HAND_REGEX)
 		if(p.search(newLine[i])):
 			k = k+1
 			tmpLine = newLine[i]
 			handshakeLine[k] = p.sub('|',newLine[i])
 			newLine[i] = p.sub('| |',tmpLine)
 		p = re.compile(UNSUPPORTED_REGEX)
 		if(p.search(newLine[i])):
 			h = h+1
 			tmpLine = newLine[i]
 			failureLine[h] = p.sub('|',newLine[i])
 			newLine[i] = p.sub('| | |',tmpLine)
 			p = re.compile(BITS_REGEX)
 			tmpLine = newLine[i]
 			failureLine[h] = p.sub('|',failureLine[h])
 			newLine[i] = p.sub('|', tmpLine)
 		p = re.compile(USER_AGENT_REGEX)
 		print newLine[i]
 		if(p.search(newLine[i])):
 			tmpLine = newLine[i]
 			failureLine[h] = p.sub('|',failureLine[h])
 			newLine[i] = failureLine[h]
 			print newLine[i] 
 			print failureLine[h]
 			
 	__write_file(failfile,failureLine)
 	__write_file(handshakefile,handshakeLine)
 	__write_file(cipherfile,cipherLine)
 	__write_file(outfile,newLine)

def main(arguments):

    parser = argparse.ArgumentParser(
    	prog="T3 SSL Log Cleanup",
    	usage='%(prog)s [options]',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('infile', help="Input file", default="ssl-orig.log", type=argparse.FileType('r'))
    parser.add_argument('-of', '--failfile', help="Failure File",
                        default=sys.stdout, type=argparse.FileType('w'))
    parser.add_argument('-oh', '--handshakefile', help="Handshake File",
                        default=sys.stdout, type=argparse.FileType('w'))
    parser.add_argument('-oc', '--cipherfile', help="Cipher File",
                        default=sys.stdout, type=argparse.FileType('w')) 
    parser.add_argument('-o', '--outfile', help="Combined output File",
                        default=sys.stdout, type=argparse.FileType('w'))  
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    args = parser.parse_args(arguments)


    __build_cipher_table()
    __parse_file(args.infile, args.outfile, args.handshakefile, args.cipherfile, args.failfile)
    

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))