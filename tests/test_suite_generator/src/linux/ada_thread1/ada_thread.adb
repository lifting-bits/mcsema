--
-- Copyright (c) 2017 Trail of Bits, Inc.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--  http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

with Ada.Text_IO;use Ada.Text_IO;

procedure Ada_Thread is
  task Write_Zeros;
  task Write_Ones;

  task body Write_Zeros is
  begin
    for I in 1..5 loop
      Put ('0');
    end loop;
  end Write_Zeros;

  task body Write_Ones is
  begin
    for I in 1..5 loop
      Put ('1');
    end loop;
  end Write_Ones;

begin
    for I in 1..5 loop
      Put ('2');
    end loop;
end Ada_Thread;
