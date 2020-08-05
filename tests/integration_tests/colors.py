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

class Colors:
    class c:
        green = '\033[92m'
        yellow = '\033[93m'
        red = '\033[91m'
        magneta = '\033[95m'
        bg_yellow = '\033[43m'
        orange = '\033[38;5;202m'
    RESET = '\033[0m'


def get_result_color(total, success):
    if total == 0:
        return Colors.c.magneta
    if total == success:
        return Colors.c.green
    if success == 0:
        return Colors.c.red
    return Colors.c.yellow

def get_bin_result(result):
    if result == 1:
        return Colors.c.green
    if result == 0:
        return Colors.c.red
    return Colors.c.magneta

def clean():
    return Colors.RESET

def c(color, message):
    return color + message + clean()

def fail():
    return Colors.c.red

def succ():
    return Colors.c.green

#TODO: Not sure if it's worth to generate these for each color from attrs dynamically
def green(message):
    return c(Colors.c.green, message)

def red(message):
    return c(Colors.c.red, message)

def yellow(message):
    return c(Colors.c.yellow, message)

def magneta(message):
    return c(Colors.c.magneta, message)

def bg_yellow(message):
    return c(Colors.c.bg_yellow, message)

def orange(message):
    return c(Colors.c.orange, message)

def id(message):
    return message
