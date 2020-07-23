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

import json
import operator
import os

import colors

UNKNOWN = 0
RUN = 1
FAIL = 2
ERROR = 3
TIMEOUT = 4

_color_mapping = {
        RUN : colors.green,
        FAIL: colors.orange,
        ERROR : colors.red,
        TIMEOUT: colors.magneta,
        UNKNOWN : colors.id,
        }

class TCData:
    def __init__(self, basename = None, bin_p = None, recompiled_p = None):
        self.binary = bin_p
        self.recompiled = recompiled_p
        self.basename = basename
        self.total = 0
        self.success = 0
        self.cases = {}
        self.ces = {}

    def is_recompiled(self):
        return self.recompiled is not None

    def get_result_color(self):
        if self.total == 0:
            return colors.magneta

        if self.total == self.success:
            return colors.green

        if self.success == 0:
            return colors.red

        return colors.orange

    def print(self, verbosity):
        end = "\n"
        if verbosity == 0:
            end = " "

        print("{:<30s}".format(self.get_result_color()(self.basename)), end=end)
        if not self.is_recompiled():
            print("\tRecompilation failed: ERROR")
            return

        if self.total == 0:
            print(colors.magneta("\tNo tests were executed"))
            return

        if verbosity == 0:
            print(colors.get_result_color(self.total, self.success) +
                  "{:>5s}".format(str(self.success) + "/" + str(self.total)) +
                  colors.clean())
        elif verbosity == 1:
            for case, val in sorted(self.cases.items(), key = operator.itemgetter(0)):
                print(" " * 2, _color_mapping[val](case))

    def print_ces(self):
        for case, ce in self.ces.items():
            print(colors.red(self.basename) + ': '+ ('without_args' if not case else case))
            print(ce)

    def get(self, test_case):
        return self.cases.get(test_case, UNKNOWN)

    def outer_get(self, name, test_case):
        if self and name == self.basename:
            return self.get(test_case)
        return UNKNOWN

class _MyEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

def _object_hook(d):
    if "binary" in d:
        obj = TCData()
        obj.__dict__.update(d)
        return obj
    return d

# SQL serialization may be useful as well
def store_json(root, filename):
    if os.path.isfile(filename):
        print("Log file already exists")
        return
    with open(filename, 'w') as f:
        json.dump(root, f, cls=_MyEncoder, indent=4)

def load_json(filename):
    with open(filename, 'r') as f:
        return json.load(f, object_hook = _object_hook)


class _Format:
    l_header = 25

    def header(self, message):
        self._header = message
        self.h_queued = True

    def case(self, message):
        self._case = message

    def _header_dump(self):
        if not self.h_queued:
            return
        self.h_queued = False

        printed = self._header.ljust(_Format.l_header)
        self.h_fill = len(printed)

        print(printed, end="")
        self.present_header = True

    def _case_dump(self):
        fill = 0 if self.present_header else self.h_fill
        printed = " " * fill + "|" + self._case.ljust(_Format.l_header) + "|"

        print(printed, end="")
        self.present_header = False

    def _res_dump(self, result):
        print(" " + str(result) + " |", end="")

    # TODO: Print something else than numbers with verbosity = 2
    def dump(self, results, verbosity, original):

        # Print everything and really verbose
        if verbosity == 2:
            self._header_dump()
            self._case_dump()
            self._res_dump(original)
            for r in results:
                print(" ", _color_mapping[r](str(r)), " |", end="")
            print()

        if verbosity == 0:
            if all(r == original for r in results):
                return

            self._header_dump()
            self._case_dump()
            self._res_dump(original)
            for r in results:
                if r == original:
                    print(" " * 3 + "|", end="")
                else:
                    print(" ", _color_mapping[r](str(r)), " |", end="")
            print()

# Compare test results to some base and print them in reasonable way
# f is formatter -> first suite name and then case are preset and when dump() is called
# actual results are printed based on verbosity level
def compare(base, results, formatter, full):
    # first we need to sort the items
    s_base = sorted(base.items(), key=operator.itemgetter(0))

    for entry in s_base:

        suite_name, tcdata = entry
        formatter.header(suite_name)

        for case_name, case_result in tcdata.cases.items():

            formatter.case(case_name)
            r_case_results = []

            for r in results:
                r_tcdata = r.get(suite_name, None)
                r_case_results.append(r_tcdata.outer_get(tcdata.basename, case_name))
            formatter.dump(r_case_results, full, case_result)
