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

class InvalidFunctionException(Exception):
  pass

class CompatAnvillMemory(object):
  def map_byte(self, ea, val, can_write, can_exec):
    pass

class CompatAnvillProgram(object):
  def __init__(self):
    self._memory = CompatAnvillMemory()

  def get_function(self, ea):
    return None

  def get_variable(self, ea):
    return None

  def add_symbol(self, ea, name):
    pass

  def add_variable_declaration(self, *args, **kargs):
    return False

  def add_variable_definition(self, *args, **kargs):
    return False

  def add_function_definition(self, *args, **kargs):
    return False

  def add_function_declaration(self, *args, **kargs):
    return False

  def try_add_referenced_entity(self, *args, **kargs):
    return False

  def memory(self):
    return self._memory

def get_program(*args, **kargs):
  return CompatAnvillProgram()
