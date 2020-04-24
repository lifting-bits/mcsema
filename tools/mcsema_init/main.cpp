/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mcsema/CFG/FromProto.h>

#include <iostream>
#include <string>


std::string help() {
  std::string out;
  out += "usage: mcsema-init input output \n";
  out += "\tinput: CFG file produced by a mcsema frontend\n";
  out += "\toutput: path to mcsema-ws database. If db already exists, entries from cfg are added only if db does not contain such module already.";
  return out;
}

// Note(lukas): For now we do not use gflags as there are almost no options and it introduces
//              a dependency. For the same reason `std::cout` is used, opposed to glog.
int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cout << help();
    return 0;
  }
  mcsema::cfg::FromProto(argv[1], argv[2]);
  return 0;
}
