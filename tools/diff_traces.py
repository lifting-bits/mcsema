#!/usr/bin/env python

# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import itertools

def diff_line(lifted_parts, native_parts, i, prev_value_lifted, prev_value_native):

  # Print out the registers every now and then.
  if not (i % 10):
    print "<tr>"
    for part in lifted_parts:
      reg_name, _ = part.split("=")
      print "<td>{}</td>".format(reg_name)
    print "</tr>"

  print "<tr id=l{}>".format(i)

  new_lifted_vals = set()
  new_native_vals = set()

  for lifted_part, native_part in zip(lifted_parts, native_parts):
    reg_name, lifted_val = lifted_part.split("=")
    native_reg_name, native_val = native_part.split("=")
    assert reg_name == native_reg_name
    print "<td>"
    if lifted_val == native_val:
      print lifted_val
    else:
      if lifted_val in prev_value_lifted:
        print '<a href="#l{}">{}</a>'.format(prev_value_lifted[lifted_val], lifted_val)
      else:
        print lifted_val
      print "<br/>"
      if native_val in prev_value_native:
        print '<a href="#l{}">{}</a>'.format(prev_value_native[native_val], native_val)
      else:
        print native_val
    print "</td>"
    new_lifted_vals.add(lifted_val)
    new_native_vals.add(native_val)

  print "</tr>"

  for lifted_val in new_lifted_vals:
    prev_value_lifted[lifted_val] = i

  for native_val in new_native_vals:
    prev_value_native[native_val] = i

class BufferredLineIter(object):
  def __init__(self, file):
    self.line_iter = iter(file_obj)
    self.pending_lines = []
    self.i = 0

  def get(self):
    self.i = 0

    if len(self.pending_lines):
      line = self.pending_lines[0]
      self.pending_lines.pop(0)
      return line

    try:
      return next(self.line_iter)
    except:
      return ""

  def try_get(self):
    if self.i < len(self.pending_lines):
      line = self.pending_lines[self.i]
      self.i += 1
      return line

    try:
      line = next(self.line_iter)
      self.pending_lines.append(line)
      self.i += 1
      return line
    except:
      return ""

def diff(lifted_trace, native_trace):

  prev_value_lifted = {}
  prev_value_native = {}
  i = 0
  while True:
    lifted_line, native_line = lifted_trace.get(), native_trace.get()
    if not lifted_line or not native_line:
      return

    lifted_parts = lifted_line.strip().split(",")
    native_parts = native_line.strip().split(",")

    if not len(lifted_parts) or not len(native_parts):
      return False
    
    if lifted_parts[0] != native_parts[0]:

      return False  # First difference in program counters.

    else:
      diff_line(lifted_parts, native_parts, i, prev_value_lifted, prev_value_native)
    i += 1

def main():
  arg_parser = argparse.ArgumentParser()

  arg_parser.add_argument(
      '--lifted_trace',
      help='Path to the lifted trace',
      required=True)

  arg_parser.add_argument(
      '--native_trace',
      help='Path to the lifted trace',
      required=True)

  args = arg_parser.parse_args()


  print '<table style="font-family:courier;font-size:11pt;border-color:#999999;" border=1 cellspacing=0>'
  
  with open(args.lifted_trace) as lifted_trace:
    with open(args.native_trace) as native_trace:
      diff(BufferredLineIter(lifted_trace), BufferredLineIter(native_trace))
      
  print "</table>"

if __name__ == "__main__":
  exit(main())
