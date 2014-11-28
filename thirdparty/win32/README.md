Third-Party Tools
=================

MC-Semantics requires Intel PIN 2.10 to build the testing infrastructure. The translation portion will still work without it, but if you want the unit tests, Intel PIN is required.

Download Intel Pin 2.10 (Revision 45467) for VS2010 from [Intel's site](https://software.intel.com/en-us/articles/pintool-downloads). Direct Link: [http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.10-45467-msvc10-ia32_intel64-windows.zip](http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.10-45467-msvc10-ia32_intel64-windows.zip)

Extract PIN to the "pin" directory.

## Example

The directory listing should look something like this:


     Directory of C:\git\llvm-lift\thirdparty\win32\pin

    07/30/2014  10:56 AM    <DIR>          .
    07/30/2014  10:56 AM    <DIR>          ..
    07/30/2014  10:55 AM    <DIR>          doc
    07/30/2014  10:55 AM    <DIR>          extras
    07/30/2014  10:55 AM    <DIR>          ia32
    07/30/2014  10:55 AM    <DIR>          intel64
    07/30/2014  10:55 AM             7,525 LICENSE
    07/30/2014  10:55 AM               195 pin.bat
    07/30/2014  10:55 AM            25,103 README
    07/30/2014  10:55 AM                42 redist.txt
    07/30/2014  10:55 AM    <DIR>          source
    07/30/2014  10:56 AM             1,409 vsdbg.bat
