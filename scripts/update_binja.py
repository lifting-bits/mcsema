#!/usr/bin/env python2

# Update script is modified from:
# https://raw.githubusercontent.com/Vector35/binaryninja-api/dev/python/examples/version_switcher.py

# Original copyright notice below

# Copyright (c) 2015-2017 Vector 35 LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import sys

from binaryninja.update import UpdateChannel, are_auto_updates_enabled, set_auto_updates_enabled, is_update_installation_pending, install_pending_update
from binaryninja import core_version
import datetime

channel = None
versions = []


def load_channel(newchannel):
  global channel
  global versions
  if (channel is not None and newchannel == channel.name):
    print("Already on the selected channel: {}".format(newchannel))
  else:
    try:
      print("Loading channel %s" % newchannel)
      channel = UpdateChannel[newchannel]
      print("Loading versions...")
      versions = channel.versions
    except Exception:
      print("%s is not a valid channel name. Defaulting to " % chandefault)
      channel = UpdateChannel[chandefault]

def select(version):
  date = datetime.datetime.fromtimestamp(version.time).strftime('%c')
  print("Version:\t%s" % version.version)
  print("Updated:\t%s" % date)
  print("Notes:\n\n-----\n%s" % version.notes)
  print(version.update())
  if is_update_installation_pending():
    print("Installing...")
    #note that the GUI will be launched after update but should still do the upgrade headless
    install_pending_update()
  # forward updating won't work without reloading
  sys.exit()


def main():
  global channel
  done = False
  # NOTE(artem): We need the dev version, for now
  load_channel("dev")
  set_auto_updates_enabled(True)
  select(channel.latest_version)

if __name__ == "__main__":
  try:
    main()
  except Exception as e:
    print("Binary Ninja update may have failed. Caught an exception trying to update: {}".format(str(e)))
