# Kernel32.dll Translation Test

This is a large test meant to showcase many features of mc-sema, and it makes for a great demo.

The test takes kernel32.dll, recovers control flow, transaltes the CFG to bitcode, and re-emits a new DLL (zernel32.dll). This new DLL can be used in place of kernel32.dll inside of calc.exe. 

**Unlike the other demos, this one uses Release mode tools by default.** If you want to use the Debug verisons, change the _PATH text files to point to the Debug path.


## Limitations

Currently this demo will **only work on Windows 7 32-bit**. No, Using a 32-bit Windows 7 kernel32.dll on Windows 7 64-bit will not work. 


## Prerequisites

* Find a kernel32.dll from Windows 7 32-bit. Place it in this directory. The one we tested with has MD5 sum 5553784d774ca845380650e010bbda2c. 

* Find calc.exe from Windows 7 32-bit. Make two copies of it. Name one `calc_original.exe` and one `calc.exe`. 

* Copy `%SystemRoot%\System32\en-US\calc.exe.mui` to `.\en-US\calc.exe.mui`. This is needed for calc to run. 

* Make sure calc.exe runs form this directory.

* Open the calc.exe in this directory in your favorite hex editor and change all instances of KERNEL32 to ZERNEL32.

## Demo Instructions


Set up the demo environment:

    env.bat

Gather only the needed imports from the original calc.exe for us to transalte

    "%IDA_PATH%\idaq.exe" -B -S"%SCRIPT_PATH%\imports_for_dll.py -m kernel32 -o imps.txt" calc_original.exe

Generate import stubs so that zernel32 can have a correct import table

    "%IDA_PATH%\idaq.exe" -B -S"%SCRIPT_PATH%\fake_imports.py --std-defs ..\..\std_defs\std_defs.txt --outdir ." kernel32.dll

Recover the CFG of all used imports

    "%IDA_PATH%\idaq.exe" -B -S"%SCRIPT_PATH%\get_cfg.py --batch --output kernel32.dll_ida.cfg --std-defs ..\..\std_defs\std_defs.txt --exports-are-apis --make-export-stubs --exports-to-lift imps.txt" kernel32.dll


Edit kernel32.dll.bat to output to zernel32.dll. **This is important**, since kernel32.dll is a protected DLL and will not be loaded from the local directory.

Run calc.exe

Cleanup for the next iteration

    cleanup.bat
