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

import logging
import inspect

_log = logging.getLogger("binja")

_DEBUG_PREFIX = ""


class StackFormatter(logging.Formatter):
  def __init__(self, fmt=None, datefmt=None):
    logging.Formatter.__init__(self, fmt, datefmt)
    self.stack_base = len(inspect.stack()) + 8

  def format(self, record):
    record.indent = '  ' * (len(inspect.stack()) - self.stack_base)
    res = logging.Formatter.format(self, record)
    del record.indent
    return res


def init(log_file):
  formatter = StackFormatter('[%(levelname)s] %(indent)s%(message)s')

  handler = None
  if not log_file == "":
    handler = logging.FileHandler(log_file)
  else:
    from sys import stdout
    handler = logging.StreamHandler(stdout)

  handler.setFormatter(formatter)

  _log.addHandler(handler)
  _log.setLevel(logging.DEBUG)


def push():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "


def pop():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]


def debug(s, *args):
  _log.debug("  {}{}".format(_DEBUG_PREFIX, str(s) % args))

def fatal(s, *args):
  _log.fatal("  {}{}".format(_DEBUG_PREFIX, str(s) % args))


def warn(s, *args):
  _log.warn("{}{}".format(_DEBUG_PREFIX, str(s) % args))


def error(s, *args):
  _log.error("  {}{}".format(_DEBUG_PREFIX, str(s) % args))
