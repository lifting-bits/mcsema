#!/usr/bin/env python3

# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import argparse
import os
import re

license_year = str(datetime.now().year)
license_info = r"""([\s\S]{0,100})Copyright \(c\) ([0-9]{4}) Trail of Bits, Inc\.
.{0,5}
.{0,5}Licensed under the Apache License, Version 2\.0 \(the \"License\"\);
.{0,5}you may not use this file except in compliance with the License\.
.{0,5}You may obtain a copy of the License at
.{0,5}
.{0,5}    http:\/\/www\.apache\.org\/licenses\/LICENSE-2\.0
.{0,5}
.{0,5}Unless required by applicable law or agreed to in writing, software
.{0,5}distributed under the License is distributed on an \"AS IS\" BASIS,
.{0,5}WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.
.{0,5}See the License for the specific language governing permissions and
.{0,5}limitations under the License\."""


def is_ignored(filename, ignore):
  if not isinstance(ignore, list):
    return False
  for ext in ignore:
    if filename.endswith(ext):
      return True


class FileInfo:
  def __init__(self, filename, start):
    self.filename = filename
    self.start = start


if __name__ == "__main__":
  # Parse args
  parser = argparse.ArgumentParser()
  parser.add_argument(
      'path',
      help='Path of directory to parse.')
  parser.add_argument(
      '-r',
      help='Recurse through sub-directories',
      action='store_true')
  parser.add_argument(
      '--ignore',
      nargs = "*",
      type = str,
      help='File extentions to ignore.')
  parser.add_argument(
      '-q', '--quiet',
      help='Supress Read Errors',
      action='store_true')
  parser.add_argument(
      '--auto-fix',
      help='Autofix out of date copyrights',
      action='store_true')
  args = parser.parse_args()
  
  regex = re.compile(license_info)

  out_of_date = []
  for dirName, subdirList, fileList in os.walk(args.path):
    for filename in fileList:
      if is_ignored(filename, args.ignore):
        continue
      
      with open(os.path.join(args.path, filename), 'r') as f:
        # Let binaries and others fail
        try:
          contents = f.read()
        except:
          if not args.quiet:
            print(f"Failed to read: {filename}")
          continue

        match = regex.match(contents)

        if match is None:
          print(f"No/bad copywrite information: {filename}")
        elif not match.group(2) == license_year:
          print(f"Out of date ({match.group(2)}): {filename}.")
          out_of_date.append(FileInfo(filename, len(match.group(1))))

    if not args.r:
      break
  
  if args.auto_fix:
    for file in out_of_date:
      with open(os.path.join(args.path, file.filename), 'r+') as f:
        f.seek(file.start + len("Copyright (c) "))
        f.write(license_year)
