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


# System import
from os import path

# Internal Imports
from cfg import EXT_MAP, EXT_DATA_MAP, RECOVER_OPTS, get_cfg
import functions as functions
import util as util
import vars as vars
import log as log

import binaryninja as bn


def recover(bv, output, os, entrypoint, do_not_recover, ignore_symbols, log_file, manual_recursive_descent, std_defs=[], recover_stack_vars=False):
  # Recover options
  RECOVER_OPTS['stack_vars'] = recover_stack_vars
  RECOVER_OPTS['manual_recursive_descent'] = manual_recursive_descent
  functions.DO_NOT_RECOVER += do_not_recover
  vars.SYM_IGNORE += ignore_symbols

  # Setup logger
  log.init(log_file)

  # Parse defs files
  log.debug('Loading definitions files')
  util.parse_defs_files(bv, os, std_defs)

  # Recover cfg
  log.debug('Starting recovery')
  log.push()
  pb_mod = CFG_pb2.Module()
  pb_mod.name = path.basename(bv.file.filename)

  log.debug('Recovering Functions')
  functions.recover_functions(bv, pb_mod, entrypoint)

  log.debug('Recovering Globals')
  vars.recover_globals(bv, pb_mod)

  log.debug('Processing Segments')
  util.recover_sections(bv, pb_mod)

  log.debug('Recovering Externals')
  util.recover_externals(bv, pb_mod)
  log.pop()

  # Save cfg
  log.debug('Saving to file: %s', output)
  with open(output, 'wb') as f:
    f.write(pb_mod.SerializeToString())

  return 0


def prepare_to_recover(bv):
  entrypoint        = bn.interaction.ChoiceField("Entrypoint: ", [f.name for f in bv.functions])
  log_file          = bn.interaction.ChoiceField("Save Log File: ", ["Yes", "No"])
  platform_choice   = bn.interaction.ChoiceField("Binary's Original Platform: ", ["linux", "windows"])
  recursive_descent = bn.interaction.ChoiceField("Enable Manual Recursive Descent: ", ["Yes", "No"])

  if not bn.get_form_input(["Disassembly Options", None, entrypoint, log_file, platform_choice, recursive_descent], "McSema Control Flow Recovery"):
    return

  entrypoint        = entrypoint.choices[entrypoint.result]
  platform_choice   = platform_choice.choices[platform_choice.result]
  if recursive_descent.choices[recursive_descent.result] == "Yes":
    recursive_descent = True
  else:
    recursive_descent = False

  default_name = path.splitext(bv.file.filename)[0] + '.cfg'
  cfg_filename = bn.get_save_filename_input(
    'Save cfg',
    '*.cfg',
    default_name
  )

  log_filename = ''
  if log_file.choices[log_file.result] == 'Yes':
    default_name = path.splitext(bv.file.filename)[0] + '.log'
    log_filename = bn.get_save_filename_input(
      'Save log',
      '*.log',
      default_name
    )

  dnr_funcs = []
  dnr_syms  = []

  if bv.file.session_data.get('mcsema_disass'):
    if bv.file.session_data['mcsema_disass'].get('dnr_funcs'):
        dnr_funcs = bv.file.session_data['mcsema_disass']['dnr_funcs']

  if bv.file.session_data.get('mcsema_disass'):
    if bv.file.session_data['mcsema_disass'].get('dnr_syms'):
        dnr_syms = bv.file.session_data['mcsema_disass']['dnr_syms']

  print("Recovering CFG...")
  recover(bv, cfg_filename, platform_choice, entrypoint, dnr_funcs, dnr_syms, log_filename, recursive_descent)
  print("CFG Recovered.")


#############
# Functions #
#############

# Do not recover function
def dnr_func(bv, func):
  if not bv.file.session_data.get('mcsema_disass'):
    bv.file.session_data['mcsema_disass'] = dict()

  if not bv.file.session_data['mcsema_disass'].get('dnr_funcs'):
    bv.file.session_data['mcsema_disass']['dnr_funcs'] = list()

  bv.file.session_data['mcsema_disass']['dnr_funcs'] += [func]


# Do recover function
def dnr_func_undo(bv, func):
  bv.file.session_data['mcsema_disass']['dnr_funcs'].remove(func)


def func_in_dnr(bv, func):
  if not bv.file.session_data.get('mcsema_disass'):
    return False

  if not bv.file.session_data['mcsema_disass'].get('dnr_funcs'):
    return False

  if not func in bv.file.session_data['mcsema_disass']['dnr_funcs']:
    return False

  return True


def func_not_in_dnr(bv, func):
  return not func_in_dnr(bv, func)


###########
# Symbols #
###########

# Do not recover symbol
def dnr_sym(bv, addr):
  if not bv.file.session_data.get('mcsema_disass'):
    bv.file.session_data['mcsema_disass'] = dict()

  if not bv.file.session_data['mcsema_disass'].get('dnr_syms'):
    bv.file.session_data['mcsema_disass']['dnr_syms'] = list()

  bv.file.session_data['mcsema_disass']['dnr_syms'] += [bv.get_symbol_at(addr)]


def dnr_sym_undo(bv, addr):
  bv.file.session_data['mcsema_disass']['dnr_syms'].remove(bv.get_symbol_at(addr))


# Check if an address is a symbol that is in the list to not recover
def sym_in_dnr(bv, addr):
  if bv.get_symbol_at(addr) is None or bv.get_symbol_at(addr).type is bn.SymbolType.FunctionSymbol:
    return False

  if not bv.file.session_data.get('mcsema_disass'):
    return False

  if not bv.file.session_data['mcsema_disass'].get('dnr_syms'):
    return False

  sym = bv.get_symbol_at(addr)

  if not sym in bv.file.session_data['mcsema_disass']['dnr_syms']:
    return False

  return True


# Make sure the symbol has not yet been recovered
def sym_not_in_dnr(bv, addr):
  return bv.get_symbol_at(addr) is not None and \
    bv.get_symbol_at(addr).type is not bn.SymbolType.FunctionSymbol and \
    not sym_in_dnr(bv, addr)


bn.PluginCommand.register_for_function('Do Not Recover Function', 'Do Not Recover Function', dnr_func, is_valid=func_not_in_dnr)
bn.PluginCommand.register_for_function('Do Recover Function', 'Do Recover Function', dnr_func_undo, is_valid=func_in_dnr)

bn.PluginCommand.register_for_address('Do Not Recover Symbol', 'Do Not Recover Symbol', dnr_sym, is_valid=sym_not_in_dnr)
bn.PluginCommand.register_for_address('Do Recover Symbol', 'Do Recover Symbol', dnr_sym_undo, is_valid=sym_in_dnr)

bn.PluginCommand.register('Disassemble Binary', 'Disassemble Binary', prepare_to_recover)
