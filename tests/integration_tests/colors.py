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
