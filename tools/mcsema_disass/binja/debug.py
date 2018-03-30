# Copyright (c) 2017 Trail of Bits, Inc.
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
import util

log = logging.getLogger(util.LOGNAME)


_DEBUG_PREFIX = ""

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  log.debug("{}{}".format(_DEBUG_PREFIX, str(s)))

def WARN(s):
  log.warn("{}{}".format(_DEBUG_PREFIX, str(s)))

def ERROR(s):
  log.error("{}{}".format(_DEBUG_PREFIX, str(s)))

  