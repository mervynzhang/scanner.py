#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# 
#   Copyright (C) 2018-2020 SCANOSS LTD
#  
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#  
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#  
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.
#  

import argparse
from pathlib import Path
import json
from json.decoder import JSONDecodeError
from binaryornot.check import is_binary
import requests
import os
import sys
import uuid

import hashlib
from crc32c import crc32

# 64k Max post size
MAX_POST_SIZE = 64 * 1024

MAX_LONG_LINE_CHARS = 1000

RESULT_FILE = "scan-result.json"

WFP_FILE_START = "file="

# List of extensions that are ignored
FILTERED_EXT = ["", "png", "html", "xml", "svg", "yaml", "yml", "txt", "json", "gif", "md", "test", "cfg", "pdf",
                "properties", "jpg", "vim", "sql", "result", "template", 'tiff', 'bmp', 'DS_Store', 'eot', 'otf', 'ttf', 'woff', 'rgb', 'conf', "whl", "o", "ico", "wfp"]

FILTERED_DIRS = ["/.git/", "/.svn/", "/.eggs/", "__pycache__", "/node_modules", "/vendor"]

DEFAULT_URL="https://osskb.org/api/scan/direct"
SCANOSS_SCAN_URL = os.environ.get("SCANOSS_SCAN_URL") if os.environ.get("SCANOSS_SCAN_URL") else DEFAULT_URL
SCANOSS_KEY_FILE = ".scanoss-key"

SCAN_TYPES = ['ignore', 'identify', 'blacklist']


def main():
  api_key = None
  parser = argparse.ArgumentParser(description='Simple scanning agains SCANOSS API.')


  parser.add_argument('scan_dir', metavar='DIR', type=str, nargs='?',
                    help='A folder to scan')
  parser.add_argument('--wfp',  type=str,
                    help='Scan a WFP File')
  parser.add_argument('--ignore',  type=str,
                      help='Scan and ignore components in SBOM file')
  parser.add_argument('--identify', nargs=1, type=str,
                      help='Scan and identify components in SBOM file')
  parser.add_argument('--blacklist', nargs=1, type=str,
                      help='Scan and blacklist components in SBOM file')
  parser.add_argument('--output', '-o', nargs=1, type=str, help='Optional name for the result file.')
  parser.add_argument('--format', '-f', nargs=1, type=str, choices=['plain','spdx','cyclonedx'], help='Optional format of the scan result')

  args = parser.parse_args()
  # Check for SCANOSS Key
  home = Path.home()
  scanoss_keyfile = str(home.joinpath(SCANOSS_KEY_FILE))
  if os.path.isfile(scanoss_keyfile):
    # Read key from file
    with open(scanoss_keyfile) as f:
      api_key = f.readline().strip()
  
  
  # Check if scan type has been declared

  scantype = ""
  
  sbom_path = ""
  if args.ignore:
    scantype = 'ignore'
    sbom_path = args.ignore
  elif args.identify:
    scantype = 'identify'
    sbom_path = args.identify
  elif args.blacklist:
    scantype = 'blacklist'
    sbom_path = args.blacklist

  if args.output:
    RESULT_FILE = args.output
  
  # Perform the scan
  if args.scan_dir:
    print("Scanning directory: %s" % args.scan_dir)
    if not os.path.isdir(args.scan_dir):
      print("Invalid directory: %s" % args.scan_dir)
      parser.print_help()
      exit(1)
    scan_folder(args.scan_dir, api_key, scantype, sbom_path, args.format)
  elif args.wfp:
    print("Scanning wfp file: ", args.wfp)
    scan_wfp(args.wfp,api_key, scantype, sbom_path, format=args.format)


def valid_folder(folder):
  for excluded in FILTERED_DIRS:
    if excluded in folder:
      return False
  return True


def scan_folder(dir: str, api_key: str, scantype: str, sbom_path: str, format: str):
  """ Performs a scan of the folder given

  Parameters
  ----------
  dir : str
    The folder containing the files to be scanned
  api_key : str
    A valid SCANOSS API key
  scantype: str
    A valid scan type (ignore, identify, blacklist)
  sbom_path: str
    A path to a valid CycloneDX or SPDX 2.2 JSON document.
  """

  wfp = ''
  # This is a dictionary that is used to perform a lookup of a file name using the corresponding file index
  files_conversion = {} if not format else None
  # We assign a number to each of the files. This avoids sending the file names to SCANOSS API,
  # thus hiding the names and the structure of the project from SCANOSS API.
  files_index = 0
  for root, sub, files in os.walk(dir):
    if valid_folder(root):
      for file in [f for f in files if os.path.splitext(f)[1][1:] not in FILTERED_EXT]:
        files_index += 1
        path = os.path.join(root, file)
        if files_conversion:
          files_conversion[str(files_index)] = path          
          wfp += wfp_for_file(files_index, path)
        else:
          wfp += wfp_for_file(file, path)
        if files_index % 100 == 0:
          print("Generating WFP: %d files processed" % files_index, end='\r')
  print()
  with open('scan.wfp', 'w') as f:
    f.write(wfp)
  scan_wfp('scan.wfp', api_key, scantype,
                       sbom_path, files_conversion, format)
  


def scan_wfp(wfp_file: str, api_key: str, scantype: str, sbom_path: str, files_conversion = None, format = None):
  file_count = count_files_in_wfp_file(wfp_file)
  print("Scanning %s files with format %s" % (file_count, format))
  cur_files = 0
  cur_size = 0
  wfp = ""
  with open(RESULT_FILE,"w") as rf:
    rf.write("{\n")
  with open(wfp_file) as f:
    for line in f:
      wfp += "\n" + line
      cur_size += len(line.encode('utf-8'))
      if WFP_FILE_START in line:
        cur_files += 1
        if cur_size >= MAX_POST_SIZE:
          print("Scanned %d/%d files" % (cur_files, file_count), end='\r')
          # Scan current WFP and store
          scan_resp = do_scan(wfp, api_key, scantype, sbom_path, format)
          with open(RESULT_FILE,"a") as rf:
            for key, value in scan_resp.items():
              file_key = files_conversion[key] if files_conversion else key
              rf.write("\"%s\":%s,\n" % (file_key, json.dumps(value, indent=4)))
          cur_size = 0
          wfp = ""
  if wfp:
    scan_resp = do_scan(wfp, api_key, scantype, sbom_path, format)
    first = True
    with open(RESULT_FILE, "a") as rf:
      for key, value in scan_resp.items():
        file_key = files_conversion[key] if files_conversion else key
        if first:
          rf.write("\"%s\":%s\n" % (file_key, json.dumps(value, indent=4)))
          first = False
        else:
          rf.write(",\"%s\":%s\n" % (file_key, json.dumps(value, indent=4)))
  with open(RESULT_FILE,"a") as rf:
    rf.write("}")
  print()
  print("Scan finished successfully")

def count_files_in_wfp_file(wfp_file: str):
  count = 0
  with open(wfp_file) as f:
    for line in f:
      if "file=" in line:
        count += 1
  return count

def do_scan(wfp: str, api_key: str, scantype: str, sbom_path: str, format: str):
  form_data = {}
  if scantype:
    with open(sbom_path) as f:
      sbom = f.read()
    form_data = {'type': scantype, 'assets': sbom}
  if format:
    form_data['format'] = format
  headers = {}
  if api_key:
    headers['X-Session'] = api_key
  scan_files = {
      'file': ("%s.wfp" % uuid.uuid1().hex, wfp)}

  r = requests.post(SCANOSS_SCAN_URL, files=scan_files, data=form_data,
                    headers=headers)
  if r.status_code >= 400:
    print("ERROR: The SCANOSS API returned the following error: HTTP %d, %s" %
          (r.status_code, r.text))
    exit(1)
  try:
    json_resp = r.json()
    return json_resp
  except JSONDecodeError:
    print("The SCANOSS API returned an invalid JSON")
    with open('bad_json.txt', 'w') as f:
      f.write(r.text)
    exit(1)
  # Decode file names
  


"""
Winnowing Algorithm implementation for SCANOSS.

This module implements an adaptation of the original winnowing algorithm by S. Schleimer, D. S. Wilkerson and A. Aiken
as described in their seminal article which can be found here: https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf

The winnowing algorithm is configured using two parameters, the gram size and the window size. For SCANOSS the values need to be:
 - GRAM: 30
 - WINDOW: 64

The result of performing the Winnowing algorithm is a string called WFP (Winnowing FingerPrint). A WFP contains optionally
the name of the source component and the results of the Winnowing algorithm for each file.

EXAMPLE output: test-component.wfp
component=f9fc398cec3f9dd52aa76ce5b13e5f75,test-component.zip
file=cae3ae667a54d731ca934e2867b32aaa,948,test/test-file1.c
4=579be9fb
5=9d9eefda,58533be6,6bb11697
6=80188a22,f9bb9220
10=750988e0,b6785a0d
12=600c7ec9
13=595544cc
18=e3cb3b0f
19=e8f7133d
file=cae3ae667a54d731ca934e2867b32aaa,1843,test/test-file2.c
2=58fb3eed
3=f5f7f458
4=aba6add1
8=53762a72,0d274008,6be2454a
10=239c7dfa
12=0b2188c9
15=bd9c4b10,d5c8f9fb
16=eb7309dd,63aebec5
19=316e10eb
[...]

Where component is the MD5 hash and path of the component container (It could be a path to a compressed file or a URL).
file is the MD5 hash, file length and file path being fingerprinted, followed by
a list of WFP fingerprints with their corresponding line numbers.
"""
# Winnowing configuration. DO NOT CHANGE.
GRAM = 30
WINDOW = 64

# ASCII characters
ASCII_0 = 48
ASCII_9 = 57
ASCII_A = 65
ASCII_Z = 90
ASCII_a = 97
ASCII_z = 122
ASCII_LF = 10
ASCII_BACKSLASH = 92

MAX_CRC32 = 4294967296


def normalize(byte):
  """
  This function normalizes a given byte as an ASCII character

  Parameters
  ----------
  byte : int
    The byte to normalize
  """
  if byte < ASCII_0:
    return 0
  if byte > ASCII_z:
    return 0
  if byte <= ASCII_9:
    return byte
  if byte >= ASCII_a:
    return byte
  if ((byte >= 65) and (byte <= 90)):
    return byte + 32

  return 0


def skip_snippets(src: str, file: str) -> bool:
  if len(src) == 0:
    return True  
  if src[0] == "{":
    return True
  prefix = src[0:5].lower()
  if prefix.startswith("<?xml") or prefix.startswith("<html"):
    print("Skipping snippet analysis due to xml/html file: ", file)
    return True
  index = src.index('\n') if '\n' in src else len(src)
  if len(src[0:src.index('\n')]) > MAX_LONG_LINE_CHARS:
    print("Skipping snippet analysis due to long line in file: ", file)
    return True
  return False


def wfp_for_file(file: str, path: str) -> str:
  """ Returns the WFP for a file by executing the winnowing algorithm over its contents.

  Parameters
  ----------
  file: str
    The name of the file
  path : str
    The full contents of the file as a byte array.
  """
  contents = None
  binary = False
  
  with open(path, 'rb') as f:
    contents = f.read()
   
  file_md5 = hashlib.md5(
      contents).hexdigest()
  # Print file line
  wfp = 'file={0},{1},{2}\n'.format(file_md5, len(contents), file)
  # We don't process snippets for binaries.
  if is_binary(path) or skip_snippets(contents.decode(), file):
    return wfp
  # Initialize variables
  gram = ""
  window = []
  normalized = 0
  line = 1
  min_hash = MAX_CRC32
  last_hash = MAX_CRC32
  last_line = 0
  output = ""

  # Otherwise recurse src_content and calculate Winnowing hashes
  for byte in contents:

    if byte == ASCII_LF:
      line += 1
      normalized = 0
    else:
      normalized = normalize(byte)

    # Is it a useful byte?
    if normalized:

      # Add byte to gram
      gram += chr(normalized)

      # Do we have a full gram?
      if len(gram) >= GRAM:
        gram_crc32 = crc32(gram.encode('ascii'))
        window.append(gram_crc32)

        # Do we have a full window?
        if len(window) >= WINDOW:

          # Select minimum hash for the current window
          min_hash = min(window)

          # Is the minimum hash a new one?
          if min_hash != last_hash:

            # Hashing the hash will result in a better balanced resulting data set
            # as it will counter the winnowing effect which selects the "minimum"
            # hash in each window
            crc = crc32((min_hash).to_bytes(4, byteorder='little'))
            crc_hex = '{:08x}'.format(crc)
            if last_line != line:
              if output:
                wfp += output + '\n'
              output = "%d=%s" % (line, crc_hex)
            else:
              output += ',' + crc_hex

            last_line = line
            last_hash = min_hash

          # Shift window
          window.pop(0)

        # Shift gram
        gram = gram[1:]

  if output:
    wfp += output + '\n'

  return wfp


if __name__ == "__main__":
  main()
