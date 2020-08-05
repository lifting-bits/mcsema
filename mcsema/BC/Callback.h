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

#pragma once

namespace llvm {

class Function;

}  // namespace llvm
namespace mcsema {
struct NativeFunction;

// Get a callback function for an external function that can be referenced by
// internal code.
llvm::Function *GetLiftedToNativeExitPoint(const NativeFunction *cfg_func);

enum ExitPointKind { kExitPointJump, kExitPointFunctionCall };

// Get a function that goes from the current lifted state into native state,
// where we don't know where the native destination actually is.
llvm::Function *GetLiftedToNativeExitPoint(ExitPointKind);

}  // namespace mcsema
