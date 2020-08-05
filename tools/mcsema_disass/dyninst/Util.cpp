/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Util.h"

mcsema::CodeReference *AddCodeXref(mcsema::Instruction *instruction,
                                   mcsema::CodeReference_OperandType opTy,
                                   Dyninst::Address addr) {

  auto xref = instruction->add_xrefs();
  xref->set_operand_type(opTy);
  xref->set_ea(addr);
  return xref;
}
