import json
import operator

import colors

UNKNOWN = 0
RUN = 1
FAIL = 2
ERROR = 3

_color_mapping = {
        RUN : colors.green,
        FAIL: colors.magneta,
        ERROR : colors.red,
        }

class TCData:
    def __init__(self, basename = None, bin_p = None, recompiled_p = None):
        self.binary = bin_p
        self.recompiled = recompiled_p
        self.basename = basename
        self.total = 0
        self.success = 0
        self.cases = {}

    def is_recompiled(self):
        return self.recompiled is not None

    def print(self, verbosity):
        end = "\n"
        if verbosity == 0:
            end = " "

        print("{:<30s}".format(self.basename), end=end)
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


def store_json(root, filename):
    with open(filename, 'w') as f:
        json.dump(root, f, cls=_MyEncoder, indent=4)

def load_json(filename):
    with open(filename, 'r') as f:
        return json.load(f, object_hook = _object_hook)


class _Format:
    l_header = 25

    def header(message):
        printed = message.ljust(_Format.l_header)
        print(printed, end="")
        return len(printed)

    def case(message, fill):
        printed = " " * fill + "|" + message.ljust(_Format.l_header) + "|"
        print(printed, end="")
        return len(printed)


def compare(base, results, comparator, full):
    # first we need to sort the items
    s_base = sorted(base.items(), key=operator.itemgetter(0))

    for entry in s_base:

        suite_name, tcdata = entry
        h_size = _Format.header(suite_name)
        first = True

        for case_name, case_result in tcdata.cases.items():

            c_size = _Format.case(case_name, 0 if first else h_size)
            first = False

            for r in results:
                r_tcdata = r.get(suite_name, None)
                r_case_result = r_tcdata.outer_get(tcdata.basename, case_name)
                if full == 1 or r_case_result:
                    print(" " + str(r_case_result) + " |", end="")
            print()
