import operator

import colors

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


