with Ada.Text_IO;
use Ada.Text_IO;

procedure Ada_Trinary is
  task Task1;
  task Task2;
  
  Task_Var1 : Integer := 0;
  Task_Var2 : Integer := 0;

  task body Task1 is
  begin
    for I in 1..2000 loop
      Task_Var1 := Task_Var1 + I;
      -- Put_Line ("Task 1 " & Integer'Image(Task_Var1));
    end loop;
  end Task1;

  task body Task2 is
  begin
    for I in 1..2000 loop
      Task_Var2 := Task_Var2 + I;
      -- Put_Line ("Task 2 " & Integer'Image(Task_Var2));
    end loop;
  end Task2;

begin
	loop
	    -- Put_Line ("Task 2 " & Integer'Image(Task_Var2) & " Task 1 " & Integer'Image(Task_Var1));
	    delay Duration(0.1);
    	exit when Task_Var1 = Task_Var2;
 	end loop;
   	Put_Line ("Test Passed " & Integer'Image(Task_Var1));
end Ada_Trinary;
