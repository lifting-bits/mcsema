# About the Demos

The demos serve both as demonstrations of the mc-sema's functionality and as regression tests to ensure previous functionality works after changes.

The output of each demo appears after its description.

The demos live in `mc-sema\tests` in the source tree. These demos require that a **debug version** of the mc-sema be built prior to execution. 

The output may differ in debug statements from what you see. Demos are tested by using IDAPython as the CFG recovery script.

## demo1

Test translating of a simple NASM generated COFF object

     C:\dev\llvm-new\mc-sema\tests>demo1.bat
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test1.cfg
     getFunc: Starting at 0x1
     1:      addl    $1, %eax
     4:      ret
     getFunc: Function recovery complete for  func at 1
     Adding entry point: demo1_entry
     demo_driver1.c
     0xC -> 0xD
     
## demo2

Translates a more complex NASM generated COFF object that includes loops. 

     C:\dev\llvm-new\mc-sema\tests>demo2
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test2.cfg
     getFunc: Starting at 0x1
     1:      movl    %eax, %ecx
     3:      xorl    %eax, %eax
     5:      incl    %eax
     6:      xorl    %ebx, %ebx
     8:      cmpl    %ecx, %ebx
     a:      je      5
     c:      addl    %eax, %eax
     e:      incl    %ebx
     f:      jmp     -9
     8:      cmpl    %ecx, %ebx
     a:      je      5
     11:     ret
     getFunc: Function recovery complete for  func at 1
     Adding entry point: demo2_entry
     demo_driver2.c
     0x100

## demo3

Translate a C compiler generated object file that includes loops, accepts arguments, and includes immediate values.

     C:\dev\llvm-new\mc-sema\tests>demo3
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test3.cfg
     demo_test3.c
     getFunc: Starting at 0x90
     90:     pushl   %ebp
     91:     movl    %esp, %ebp
     93:     subl    $12, %esp
     96:     movl    8(%ebp), %eax
     99:     movl    %eax, -8(%ebp)
     9c:     movl    12(%ebp), %ecx
     9f:     movl    %ecx, -12(%ebp)
     a2:     movl    -8(%ebp), %edx
     a5:     movb    (%edx), %al
     a7:     movb    %al, -1(%ebp)
     aa:     movsbl  -1(%ebp), %ecx
     ae:     testl   %ecx, %ecx
     b0:     je      53
     b2:     movsbl  -1(%ebp), %edx
     b6:     cmpl    $47, %edx
     b9:     jne     8
     bb:     movl    -12(%ebp), %eax
     be:     movb    $92, (%eax)
     c1:     jmp     8
     cb:     movl    -8(%ebp), %eax
     ce:     addl    $1, %eax
     d1:     movl    %eax, -8(%ebp)
     d4:     movl    -12(%ebp), %ecx
     d7:     addl    $1, %ecx
     da:     movl    %ecx, -12(%ebp)
     dd:     movl    -8(%ebp), %edx
     e0:     movb    (%edx), %al
     e2:     movb    %al, -1(%ebp)
     e5:     jmp     -61
     aa:     movsbl  -1(%ebp), %ecx
     ae:     testl   %ecx, %ecx
     b0:     je      53
     e7:     movl    %ebp, %esp
     e9:     popl    %ebp
     ea:     ret
     c3:     movl    -12(%ebp), %ecx
     c6:     movb    -1(%ebp), %dl
     c9:     movb    %dl, (%ecx)
     cb:     movl    -8(%ebp), %eax
     ce:     addl    $1, %eax
     d1:     movl    %eax, -8(%ebp)
     d4:     movl    -12(%ebp), %ecx
     d7:     addl    $1, %ecx
     da:     movl    %ecx, -12(%ebp)
     dd:     movl    -8(%ebp), %edx
     e0:     movb    (%edx), %al
     e2:     movb    %al, -1(%ebp)
     e5:     jmp     -61
     getFunc: FunctioprocessDataSection: section range (0, 80)
     n recovery complete for  func at 90
     Adding entry point: demo3_entry
     inserting global data section named data_0x0
     demo_driver3.c
     /first/test/path -> \first\test\path
     

## demo4

Translate a C compiler generated COFF boject that calls external functions to allocate memory and returns pointers to calling code.
     
     C:\dev\llvm-new\mc-sema\tests>demo4
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test4.obj
     demo_test4.c
     getFunc: Starting at 0x90
     90:     pushl   %ebp
     91:     movl    %esp, %ebp
     93:     subl    $16, %esp
     96:     movl    8(%ebp), %eax
     99:     pushl   %eax
     9a:     calll   0
     External call to: strlen
     9f:     addl    $4, %esp
     a2:     addl    $1, %eax
     a5:     movl    %eax, -4(%ebp)
     a8:     movl    -4(%ebp), %ecx
     ab:     pushl   %ecx
     ac:     calll   0
     External call to: malloc
     b1:     addl    $4, %esp
     b4:     movl    %eax, -8(%ebp)
     b7:     cmpl    $0, -8(%ebp)
     bb:     je      96
     bd:     movl    8(%ebp), %edx
     c0:     movl    %edx, -16(%ebp)
     c3:     movl    -8(%ebp), %eax
     c6:     movl    %eax, -12(%ebp)
     c9:     movl    -4(%ebp), %ecx
     cc:     pushl   %ecx
     cd:     pushl   $0
     cf:     movl    -8(%ebp), %edx
     d2:     pushl   %edx
     d3:     calll   0
     External call to: memset
     d8:     addl    $12, %esp
     db:     movl    -16(%ebp), %eax
     de:     movsbl  (%eax), %ecx
     e1:     testl   %ecx, %ecx
     e3:     je      49
     e5:     movl    -16(%ebp), %edx
     e8:     movsbl  (%edx), %eax
     eb:     cmpl    $47, %eax
     ee:     jne     8
     f0:     movl    -12(%ebp), %ecx
     f3:     movb    $92, (%ecx)
     f6:     jmp     10
     102:    movl    -16(%ebp), %edx
     105:    addl    $1, %edx
     108:    movl    %edx, -16(%ebp)
     10b:    movl    -12(%ebp), %eax
     10e:    addl    $1, %eax
     111:    movl    %eax, -12(%ebp)
     114:    jmp     -59
     db:     movl    -16(%ebp), %eax
     de:     movsbl  (%eax), %processDataSection: section range (0, 80)
     ecx
     e1:     testl   %ecx, %ecx
     e3:     je      49
     116:    movl    -8(%ebp), %eax
     119:    jmp     4
     11f:    movl    %ebp, %esp
     121:    popl    %ebp
     122:    ret
     f8:     movl    -12(%ebp), %edx
     fb:     movl    -16(%ebp), %eax
     fe:     movb    (%eax), %cl
     100:    movb    %cl, (%edx)
     102:    movl    -16(%ebp), %edx
     105:    addl    $1, %edx
     108:    movl    %edx, -16(%ebp)
     10b:    movl    -12(%ebp), %eax
     10e:    addl    $1, %eax
     111:    movl    %eax, -12(%ebp)
     114:    jmp     -59
     11d:    xorl    %eax, %eax
     11f:    movl    %ebp, %esp
     121:    popl    %ebp
     122:    ret
     getFunc: Function recovery complete for  func at 90
     Adding entry point: demo4_entry
     inserting global data section named data_0x0
     demo_driver4.c
     /first/test/path -> \first\test\path

## demo5

Translates a C compiler generated COFF object that calls external function calls that have side effects. In this case, it creates and deletes files on the filesystem.

     C:\dev\llvm-new\mc-sema\tests>demo5
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test5.obj
     demo_test5.c
     getFunc: Starting at 0x90
     90:     pushl   %ebp
     91:     movl    %esp, %ebp
     93:     pushl   %ecx
     94:     pushl   $0
     96:     pushl   $128
     9b:     pushl   $3
     9d:     pushl   $0
     9f:     pushl   $1
     a1:     pushl   $2147483648
     a6:     movl    8(%ebp), %eax
     a9:     pushl   %eax
     aa:     calll   *0
     Calling symbol: CreateFileA
     b0:     movl    %eax, -4(%ebp)
     b3:     cmpl    $-1, -4(%ebp)
     b7:     je      16
     b9:     movl    -4(%ebp), %ecx
     bc:     pushl   %ecx
     bd:     calll   *0
     Calling symbol: CloseHandle
     c3:     xorl    %eax, %eax
     c5:     jmp     5
     cc:     movl    %ebp, %esp
     ce:     popl    %ebp
     cf:     ret
     c9:     orl     $-1, %eax
     cc:     movl    %ebp, %esp
     ce:     popl    %ebp
     cf:     retprocessDataSection: section range (0, 80)
     
     getFunc: Function recovery complete for  func at 90
     Adding entry point: demo5_entry
     inserting global data section named data_0x0
     demo_driver5.c
     -1
     0


## demo6

Translates a C compiler generated COFF object that has several subroutines referenced by the main routine. It also calls external functions and allocates memory via malloc.


     C:\dev\llvm-new\mc-sema\tests>demo6
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test6.obj
     demo_test6.c
     getFunc: Starting at 0x90
     90:     pushl   %ebp
     91:     movl    %esp, %ebp
     93:     subl    $12, %esp
     96:     movl    $0, -4(%ebp)
     9d:     movl    12(%ebp), %eax
     a0:     pushl   %eax
     a1:     calll   0
     External call to: malloc
     a6:     addl    $4, %esp
     a9:     movl    %eax, -8(%ebp)
     ac:     jmp     9
     b7:     movl    -4(%ebp), %edx
     ba:     cmpl    12(%ebp), %edx
     bd:     jge     46
     bf:     movl    -4(%ebp), %eax
     c2:     movl    8(%ebp), %ecx
     c5:     movl    (%ecx,%eax,4), %edx
     c8:     movl    %edx, -12(%ebp)
     cb:     movl    -12(%ebp), %eax
     ce:     pushl   %eax
     cf:     calll   0
     Symbol not found, maybe a local call
     Found local call to: 100
     d4:     addl    $4, %esp
     d7:     testl   %eax, %eax
     d9:     jne     16
     db:     movl    -12(%ebp), %ecx
     de:     pushl   %ecx
     df:     movl    -12(%ebp), %edx
     e2:     pushl   %edx
     e3:     calll   0
     Symbol not found, maybe a local call
     Found local call to: 150
     e8:     addl    $8, %esp
     eb:     jmp     -63
     ae:     movl    -4(%ebp), %ecx
     b1:     addl    $1, %ecx
     b4:     movl    %ecx, -4(%ebp)
     b7:     movl    -4(%ebp), %edx
     ba:     cmpl    12(%ebp), %edx
     bd:     jge     46
     ed:     movl    -8(%ebp), %eax
     f0:     movb    $2, 1(%eax)
     f4:     movl    %ebp, %esp
     f6:     popl    %ebp
     f7:     ret
     eb:     jmp     -63
     getFunc: Function recovery complete for  func at 90
     getFunc: Starting at 0x150
     150:    pushl   %ebp
     151:    movl    %esp, %ebp
     153:    subl    $12, %esp
     156:    movl    8(%ebp), %eax
     159:    movl    %eax, -8(%ebp)
     15c:    movl    12(%ebp), %ecx
     15f:    movl    %ecx, -12(%ebp)
     162:    movl    -8(%ebp), %edx
     165:    movb    (%edx), %al
     167:    movb    %al, -1(%ebp)
     16a:    movsbl  -1(%ebp), %ecx
     16e:    testl   %ecx, %ecx
     170:    je      53
     172:    movsbl  -1(%ebp), %edx
     176:    cmpl    $47, %edx
     179:    jne     8
     17b:    movl    -12(%ebp), %eax
     17e:    movb    $92, (%eax)
     181:    jmp     8
     18b:    movl    -8(%ebp), %eax
     18e:    addl    $1, %eax
     191:    movl    %eax, -8(%ebp)
     194:    movl    -12(%ebp), %ecx
     197:    addl    $1, %ecx
     19a:    movl    %ecx, -12(%ebp)
     19d:    movl    -8(%ebp), %edx
     1a0:    movb    (%edx), %al
     1a2:    movb    %al, -1(%ebp)
     1a5:    jmp     -61
     16a:    movsbl  -1(%ebp), %ecx
     16e:    testl   %ecx, %ecx
     170:    je      53
     1a7:    movl    %ebp, %esp
     1a9:    popl    %ebp
     1aa:    ret
     183:    movl    -12(%ebp), %ecx
     186:    movb    -1(%ebp), %dl
     189:    movb    %dl, (%ecx)
     18b:    movl    -8(%ebp), %eax
     18e:    addl    $1, %eax
     191:    movl    %eax, -8(%ebp)
     194:    movl    -12(%ebp), %ecx
     197:    addl    $1, %ecx
     19a:    movl    %ecx, -12(%ebp)
     19d:    movl    -8(%ebp), %edx
     1a0:    movb    (%edx), %al
     1a2:    movb    %al, -1(%ebp)
     1a5:    jmp     -61
     getFunc: Function recovery complete for  func at 150
     getFunc: Starting at 0x100
     100:    pushl   %ebp
     101:    movl    %esp, %ebp
     103:    subl    $12, %esp
     106:    movl    $1, -8(%ebp)
     10d:    movl    8(%ebp), %eax
     110:    pushl   %eax
     111:    calll   0
     External call to: strlen
     116:    addl    $4, %esp
     119:    movl    %eax, -4(%ebp)
     11c:    cmpl    $1, -4(%ebp)
     120:    jle     39
     122:    movl    8(%ebp), %ecx
     125:    movb    (%ecx), %dl
     127:    movb    %dl, -9(%ebp)
     12a:    movl    8(%ebp), %eax
     12d:    addl    -4(%ebp), %eax
     130:    movb    -1(%eax), %cl
     133:    movb    %cl, -10(%ebp)
     136:processDataSection: section range (0, 80)
             movsbl  -9(%ebp), %edx
     13a:    movsbl  -10(%ebp), %eax
     13e:    cmpl    %eax, %edx
     140:    jne     7
     142:    movl    $0, -8(%ebp)
     149:    movl    -8(%ebp), %eax
     14c:    movl    %ebp, %esp
     14e:    popl    %ebp
     14f:    ret
     149:    movl    -8(%ebp), %eax
     14c:    movl    %ebp, %esp
     14e:    popl    %ebp
     14f:    ret
     getFunc: Function recovery complete for  func at 100
     Warning: address 1 is not in a data section.
     Warning: address ffffffffffffffff is not in a data section.
     Adding entry point: demo6_entry
     inserting global data section named data_0x0
     demo_driver6.c
     a == foo
     b == /stuff/
     c == bar
     a == foo
     b == \stuff\
     c == bar


## demo7

Calls external functions and contains a data reference that must be translated

     C:\dev\llvm-new\mc-sema\tests>demo7
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test7.obj
     demo_test7.c
     processDataSection: section range (0, 80)
     processDataSection: section range (80, 84)
     getFunc: Starting at 0x94
     94:     pushl   %ebp
     95:     movl    %esp, %ebp
     97:     pushl   $0
     9c:     movl    8(%ebp), %eax
     9f:     pushl   %eax
     a0:     calll   0
     External call to: strcmp
     a5:     addl    $8, %esp
     a8:     popl    %ebp
     a9:     ret
     getFunc: Function recovery complete for  func at 94
     Adding entry point: demo7_entry
     inserting global data section named data_0x0
     inserting global data section named data_0x80
     demo_driver7.c
     i == -1
     k == 0
     j == 1


## demo8

References a non-string global variable that is used in computation. 

     C:\dev\llvm-new\mc-sema\tests>demo8
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test8.obj
     demo_test8.c
     processDataSection: section range (0, 80)
     processDataSection: section range (80, 84)
     getFunc: Starting at 0x94
     94:     pushl   %ebp
     95:     movl    %esp, %ebp
     97:     pushl   %ecx
     98:     movl    0, %eax
     9d:     movl    %eax, -4(%ebp)
     a0:     movl    0, %ecx
     a6:     addl    8(%ebp), %ecx
     a9:     movl    %ecx, 0
     af:     movl    -4(%ebp), %eax
     b2:     movl    %ebp, %esp
     b4:     popl    %ebp
     b5:     ret
     getFunc: Function recovery complete for  func at 94
     Adding entry point: demo8_entry
     inserting global data section named data_0x0
     inserting global data section named data_0x80
     demo_driver8.c
     i == 1
     k == 3
     j == 7

## demo9

Tests variable argument functions (in this case printf) and references data items that must be translated.

     C:\dev\llvm-new\mc-sema\tests>demo9
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test9.obj
     demo_test9.c
     getFunc: Starting at 0xa8
     a8:     pushl   %ebp
     a9:     movl    %esp, %ebp
     ab:     pushl   %ecx
     ac:     movl    8(%ebp), %eax
     af:     pushl   %eax
     b0:     pushl   $0
     b5:     calll   0
     External call to: printf
     ba:     addl    $8, %esp
     bd:     movl    %eax, -4(%ebp)
     c0:     movl    8(%ebp), %ecx
     c3:     pushl   %ecx
     c4:     movl    8(%ebp), %edx
     c7:     pushl   %edx
     c8:     pushl   $0
     cd:     calll   0
     External call to: printf
     d2:     addl    $12, %esp
     d5:     movl    %eax, -4(%ebp)
     d8:     movl    8(%ebp), %eax
     db:     pushl   %eax
     dc:     movl    8(%ebp), %ecx
     df:     pushl   %ecx
     e0:     movl    8(%ebp), %edx
     e3:     pushl   %edx
     e4:     pushl   $0
     e9:     calll   processDataSection: section range (0, 80)
     processDataSection: section range (80, 98)
     0
     External call to: printf
     ee:     addl    $16, %esp
     f1:     movl    %eax, -4(%ebp)
     f4:     movl    -4(%ebp), %eax
     f7:     movl    %ebp, %esp
     f9:     popl    %ebp
     fa:     ret
     getFunc: Function recovery complete for  func at a8
     Adding entry point: demo9_entry
     inserting global data section named data_0x0
     inserting global data section named data_0x80
     demo_driver9.c
     abc
     abc, abc
     abc, abc, abc

## demo10

Tests data that references other data and calls external functions

     C:\dev\llvm-new\mc-sema\tests>demo10
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test10.obj
     demo_test10.c
     getFunc: Starting at 0xcf
     cf:     pushl   %ebp
     d0:     movl    %esp, %ebp
     d2:     pushl   %ecx
     d3:     movl    $0, -4(%ebp)
     da:     jmp     9
     e5:     cmpl    $10, -4(%ebp)
     e9:     jae     56
     eb:     movl    -4(%ebp), %ecx
     ee:     cmpl    $0, (,%ecx,4)
     f6:     je      41
     f8:     movl    -4(%ebp), %edx
     fb:     movl    (,%edx,4), %eax
     102:    movl    (%eax), %ecx
     104:    pushl   %ecx
     105:    movl    -4(%ebp), %edx
     108:    movl    (,%edx,4), %eax
     10f:    pushl   %eax
     110:    movl    -4(%ebp), %ecx
     113:    pushl   %ecx
     114:    pushl   $0
     119:    calll   0
     External call to: printf
     11e:    addl    $16, %esp
     121:    jmp     -71
     dc:     movl    -4(%ebp), %eax
     df:     addlprocessDataSection: section range (0, 80)
     processDataSection: section range (80, cf)
     processDataSection: Adding data blob from: 80 to: 90
     processDataSection: Adding data blob from: 94 to: 9c
     processDataSection: Adding data blob from: a0 to: ac
             $1, %eax
     e2:     movl    %eax, -4(%ebp)
     e5:     cmpl    $10, -4(%ebp)
     e9:     jae     56
     123:    xorl    %eax, %eax
     125:    movl    %ebp, %esp
     127:    popl    %ebp
     128:    ret
     121:    jmp     -71
     getFunc: Function recovery complete for  func at cf
     Adding entry point: demo10_entry
     inserting global data section named data_0x0
     inserting global data section named data_0x80
     demo_driver10.c
     mydata[1] = 0081D000 => 0xAA0000
     mydata[4] = 0081D004 => 0x00BB00
     mydata[8] = 0081D008 => 0x0000CC



## demo11

Tests processing of very large data sections. The only real difference between demo10 and demo11 is the size of the data. 

     C:\dev\llvm-new\mc-sema\tests>demo11
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_test11.obj
     demo_test11.c
     getFunc: Starting at 0x4e23b1
     4e23b1: pushl   %ebp
     4e23b2: movl    %esp, %ebp
     4e23b4: pushl   %ecx
     4e23b5: movl    $0, -4(%ebp)
     4e23bc: jmp     9
     4e23c7: cmpl    $1280193, -4(%ebp)
     4e23ce: jae     56
     4e23d0: movl    -4(%ebp), %ecx
     4e23d3: cmpl    $0, (,%ecx,4)
     4e23db: je      41
     4e23dd: movl    -4(%ebp), %edx
     4e23e0: movl    (,%edx,4), %eax
     4e23e7: movl    (%eax), %ecx
     4e23e9: pushl   %ecx
     4e23ea: movl    -4(%ebp), %edx
     4e23ed: movl    (,%edx,4), %eax
     4e23f4: pushl   %eax
     4e23f5: movl    -4(%ebp), %ecx
     4e23f8: pushl   %ecx
     4e23f9: pushl   $0
     4e23fe: calll   0
     ExternprocessDataSection: section range (0, 80)
     processDataSection: section range (80, 4e23b1)
     processDataSection: Adding data blob from: 80 to: 4e2b0
     processDataSection: Adding data blob from: 4e2b4 to: 4e2bc
     processDataSection: Adding data blob from: 4e2c0 to: 4e2cc
     processDataSection: Adding data blob from: 4e2d0 to: ea710
     processDataSection: Adding data blob from: ea714 to: ea71c
     processDataSection: Adding data blob from: ea720 to: ea72c
     processDataSection: Adding data blob from: ea730 to: 186b70
     processDataSection: Adding data blob from: 186b74 to: 186b7c
     processDataSection: Adding data blob from: 186b80 to: 186b8c
     processDataSection: Adding data blob from: 186b90 to: 222fd0
     processDataSection: Adding data blob from: 222fd4 to: 222fdc
     processDataSection: Adding data blob from: 222fe0 to: 222fec
     processDataSection: Adding data blob from: 222ff0 to: 2bf430
     processDataSection: Adding data blob from: 2bf434 to: 2bf43c
     processDataSection: Adding data blob from: 2bf440 to: 2bf44c
     processDataSection: Adding data blob from: 2bf450 to: 35b890
     processDataSection: Adding data blob from: 35b894 to: 35b89c
     processDataSection: Adding data blob from: 35b8a0 to: 35b8ac
     processDataSection: Adding data blob from: 35b8b0 to: 3f7cf0
     processDataSection: Adding data blob from: 3f7cf4 to: 3f7cfc
     processDataSection: Adding data blob from: 3f7d00 to: 3f7d0c
     processDataSection: Adding data blob from: 3f7d10 to: 494150
     processDataSection: Adding data blob from: 494154 to: 49415c
     processDataSection: Adding data blob from: 494160 to: 49416c
     al call to: printf
     4e2403: addl    $16, %esp
     4e2406: jmp     -74
     4e23be: movl    -4(%ebp), %eax
     4e23c1: addl    $1, %eax
     4e23c4: movl    %eax, -4(%ebp)
     4e23c7: cmpl    $1280193, -4(%ebp)
     4e23ce: jae     56
     4e2408: xorl    %eax, %eax
     4e240a: movl    %ebp, %esp
     4e240c: popl    %ebp
     4e240d: ret
     4e2406: jmp     -74
     getFunc: Function recovery complete for  func at 4e23b1
     Adding entry point: demo11_entry
     inserting global data section named data_0x0
     inserting global data section named data_0x80
     demo_driver11.c
     readdata[80008] = 000FD000 => 0xAA0000
     readdata[80011] = 000FD004 => 0x00BB00
     readdata[80015] = 000FD008 => 0x0000CC
     readdata[240032] = 000FD000 => 0xAA0000
     readdata[240035] = 000FD004 => 0x00BB00
     readdata[240039] = 000FD008 => 0x0000CC
     readdata[400056] = 000FD000 => 0xAA0000
     readdata[400059] = 000FD004 => 0x00BB00
     readdata[400063] = 000FD008 => 0x0000CC
     readdata[560080] = 000FD000 => 0xAA0000
     readdata[560083] = 000FD004 => 0x00BB00
     readdata[560087] = 000FD008 => 0x0000CC
     readdata[720104] = 000FD000 => 0xAA0000
     readdata[720107] = 000FD004 => 0x00BB00
     readdata[720111] = 000FD008 => 0x0000CC
     readdata[880128] = 000FD000 => 0xAA0000
     readdata[880131] = 000FD004 => 0x00BB00
     readdata[880135] = 000FD008 => 0x0000CC
     readdata[1040152] = 000FD000 => 0xAA0000
     readdata[1040155] = 000FD004 => 0x00BB00
     readdata[1040159] = 000FD008 => 0x0000CC
     readdata[1200176] = 000FD000 => 0xAA0000
     readdata[1200179] = 000FD004 => 0x00BB00
     readdata[1200183] = 000FD008 => 0x0000CC

## demo_12

Tests accessing the segment registers and the pushf instruction.

    C:\git\llvm-lift\mc-sema\tests>demo12.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_test12.cfg
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --entry-symbol start --output demo_test12.cfg', 'demo_test12.obj']
    Already have driver for: start
    inserting global data section named data_0x2c
    Adding entry point: demo12_entry
    demo_driver12.c
    0x246

## demo_13

Tests complex jump tables (generated via switch() statement).

    C:\git\llvm-lift\mc-sema\tests>demo13.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_test13.obj
    demo_test13.c
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --std-defs ..\\std_defs\\std_defs.txt --entry-symbol _switches --output demo_test13.cfg', 'demo_test13.obj']
    Already have driver for: _switches
    inserting global data section named data_0x0
    inserting global data section named data_0x1e0
    Adding entry point: demo13_entry
    demo_driver13.c
    Input was zero
    Input was one
    Input was two
    Unknown input: 3
    Input was four
    Unknown input: 5
    Input was six
    Unknown input: 7
    Unknown input: 8
    Unknown input: 9
    Unknown input: 10
    Unknown input: 11
    Input was twelve
    Input was thirteen
    Unknown input: 14
    Unknown input: 15
    Unknown input: 16
    Unknown input: 17
    Unknown input: 18
    Input was nineteen
    Unknown input: 20
    Unknown input: 21
    Unknown input: 22
    Unknown input: 23
    Unknown input: 24
    Unknown input: 25
    Unknown input: 26
    Unknown input: 27
    Unknown input: 28
    Unknown input: 29
    Unknown input: 30
    Unknown input: 31
    Unknown input: 32
    Unknown input: 33
    Unknown input: 34
    Unknown input: 35
    Unknown input: 36
    Unknown input: 37
    Unknown input: 38
    Unknown input: 39
    Unknown input: 40
    Unknown input: 41
    Unknown input: 42
    Unknown input: 43
    Unknown input: 44
    Unknown input: 45
    Unknown input: 46
    Unknown input: 47
    Unknown input: 48
    Unknown input: 49
    Unknown input: 50
    Unknown input: 51
    Unknown input: 52
    Unknown input: 53
    Unknown input: 54
    Unknown input: 55
    Unknown input: 56
    Unknown input: 57
    Unknown input: 58
    Unknown input: 59
    Unknown input: 60
    Unknown input: 61
    Unknown input: 62
    Unknown input: 63
    Unknown input: 64
    Unknown input: 65
    Unknown input: 66
    Unknown input: 67
    Unknown input: 68
    Unknown input: 69
    Unknown input: 70
    Unknown input: 71
    Unknown input: 72
    Unknown input: 73
    Unknown input: 74
    Unknown input: 75
    Unknown input: 76
    Unknown input: 77
    Unknown input: 78
    Unknown input: 79
    Unknown input: 80
    Unknown input: 81
    Unknown input: 82
    Unknown input: 83
    Unknown input: 84
    Unknown input: 85
    Unknown input: 86
    Unknown input: 87
    Unknown input: 88
    Unknown input: 89
    Unknown input: 90
    Unknown input: 91
    Unknown input: 92
    Unknown input: 93
    Unknown input: 94
    Unknown input: 95
    Unknown input: 96
    Unknown input: 97
    Unknown input: 98
    Unknown input: 99
    Unknown input: 100
    Unknown input: 101
    Unknown input: 102
    Unknown input: 103
    Unknown input: 104
    Unknown input: 105
    Unknown input: 106
    Unknown input: 107
    Unknown input: 108
    Unknown input: 109
    Unknown input: 110
    Unknown input: 111
    Unknown input: 112
    Unknown input: 113
    Unknown input: 114
    Unknown input: 115
    Unknown input: 116
    Unknown input: 117
    Unknown input: 118
    Unknown input: 119
    Unknown input: 120
    Unknown input: 121
    Unknown input: 122
    Unknown input: 123
    Unknown input: 124
    Unknown input: 125
    Unknown input: 126
    Unknown input: 127
    Unknown input: 128
    Unknown input: 129
    Unknown input: 130
    Unknown input: 131
    Unknown input: 132
    Unknown input: 133
    Unknown input: 134
    Unknown input: 135
    Unknown input: 136
    Unknown input: 137
    Unknown input: 138
    Unknown input: 139
    Unknown input: 140
    Unknown input: 141
    Unknown input: 142
    Unknown input: 143
    Unknown input: 144
    Unknown input: 145
    Unknown input: 146
    Unknown input: 147
    Unknown input: 148
    Unknown input: 149
    Unknown input: 150
    Unknown input: 151
    Unknown input: 152
    Unknown input: 153
    Unknown input: 154
    Unknown input: 155
    Unknown input: 156
    Unknown input: 157
    Unknown input: 158
    Unknown input: 159
    Unknown input: 160
    Unknown input: 161
    Unknown input: 162
    Unknown input: 163
    Unknown input: 164
    Unknown input: 165
    Unknown input: 166
    Unknown input: 167
    Unknown input: 168
    Unknown input: 169
    Unknown input: 170
    Unknown input: 171
    Unknown input: 172
    Unknown input: 173
    Unknown input: 174
    Unknown input: 175
    Unknown input: 176
    Unknown input: 177
    Unknown input: 178
    Unknown input: 179
    Unknown input: 180
    Unknown input: 181
    Unknown input: 182
    Unknown input: 183
    Unknown input: 184
    Unknown input: 185
    Unknown input: 186
    Unknown input: 187
    Unknown input: 188
    Unknown input: 189
    Unknown input: 190
    Unknown input: 191
    Unknown input: 192
    Unknown input: 193
    Unknown input: 194
    Unknown input: 195
    Unknown input: 196
    Unknown input: 197
    Unknown input: 198
    Unknown input: 199
    Unknown input: 200
    Unknown input: 201
    Unknown input: 202
    Unknown input: 203
    Unknown input: 204
    Unknown input: 205
    Unknown input: 206
    Unknown input: 207
    Unknown input: 208
    Unknown input: 209
    Unknown input: 210
    Unknown input: 211
    Unknown input: 212
    Unknown input: 213
    Unknown input: 214
    Unknown input: 215
    Unknown input: 216
    Unknown input: 217
    Unknown input: 218
    Unknown input: 219
    Unknown input: 220
    Unknown input: 221
    Unknown input: 222
    Unknown input: 223
    Unknown input: 224
    Unknown input: 225
    Unknown input: 226
    Unknown input: 227
    Unknown input: 228
    Unknown input: 229
    Unknown input: 230
    Unknown input: 231
    Unknown input: 232
    Unknown input: 233
    Unknown input: 234
    Unknown input: 235
    Unknown input: 236
    Unknown input: 237
    Unknown input: 238
    Unknown input: 239
    Unknown input: 240
    Unknown input: 241
    Unknown input: 242
    Unknown input: 243
    Unknown input: 244
    Unknown input: 245
    Unknown input: 246
    Unknown input: 247
    Unknown input: 248
    Unknown input: 249
    Unknown input: 250
    Unknown input: 251
    Unknown input: 252
    Unknown input: 253
    Unknown input: 254
    Input was two hundred fifty-five

## demo14

Test translating functions with a fastcall calling convention.

    C:\git\llvm-lift\mc-sema\tests>demo14.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_test14.obj
    demo_test14.c
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --std-defs demo14_defs.txt --entry-symbol _printMessages --output demo_test14.cfg', 'demo_test14.obj']
    Already have driver for: _printMessages
    Adding entry point: demo14_entry
    demo_driver14.c
    Three arg fastcall: 00000100, 00000200, 00000300
    Two arg fastcall: 00000400, 00000500
    One arg fastcall: 00000600

## demo15

Test multiple calling conventions: fastcall, stdcall and cdecl in the same translation unit.

    C:\git\llvm-lift\mc-sema\tests>demo15.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_test15.obj
    demo_test15.c
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --std-defs ..\\std_defs\\std_defs.txt --entry-symbol _imcdecl _imstdcall@8 @imfastcall@8 --output demo_test15.cfg', 'demo_test15.obj']
    Already have driver for: _imcdecl
    Already have driver for: _imstdcall@8
    Already have driver for: @imfastcall@8
    inserting global data section named data_0x0
    Adding entry point: imcdecl
    Adding entry point: imstdcall
    Adding entry point: imfastcall
    demo_driver15.c
    stdcall args are: 00000100, 00000200
    fastcall args are: 00000300, 00000200
    cdecl args are: 00000200, 00000500
    Test Passed

## demo16

Test support for the _aullshr intrinsic emitted by Visual Studio.

    C:\git\llvm-lift\mc-sema\tests>demo16.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_test16.obj
    demo_test16.c
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --std-defs demo16_defs.txt ..\\std_defs\\std_defs. txt --entry-symbol _shiftit --output demo_test16.cfg', 'demo_test16.obj']
    Already have driver for: _shiftit
    Adding entry point: shiftit
    demo_driver16.c
    We have: 0xffffffffffff0000

## demo_fpu1

Tests floating point instruciton translation; multiplies its input by PI

     C:\dev\llvm-new\mc-sema\tests>demo_fpu1.bat
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_fpu1.obj
     demo_fpu1.c
     processDataSection: section range (0, 7c)
     processDataSection: section range (a5, ad)
     getFunc: Starting at 0x8c
     8c:     pushl   %ebp
     8d:     movl    %esp, %ebp
     8f:     subl    $8, %esp
     92:     fldl    0
     98:     fstpl   -8(%ebp)
     9b:     fldl    8(%ebp)
     9e:     fmull   -8(%ebp)
     a1:     movl    %ebp, %esp
     a3:     popl    %ebp
     a4:     ret
     getFunc: Function recovery complete for  func at 8c
     Adding entry point: demo_fpu1_entry
     inserting global data section named data_0x0
     inserting global data section named data_0xa5
     demo_driver_fpu1.c
     2.0000000000000000 -> 6.2831854820251465


## demo_sailboat

Tests a complex application that does many arithmetic operations and calls back into its parent object.

     C:\dev\llvm-new\mc-sema\tests>demo_sailboat.bat
     Could Not Find C:\dev\llvm-new\mc-sema\tests\sailboat.obj
     sailboat.c
     sailboat.c(84) : warning C4552: '<<' : operator has no effect; expected operator
     effect
     getFunc: Starting at 0x7c
     7c:     pushl   %ebp
     7d:     movl    %esp, %ebp
     7f:     subl    $56, %esp
     82:     movl    8(%ebp), %eax
     85:     pushl   %eax
     86:     calll   0
     External call to: strlen
     8b:     addl    $4, %esp
     8e:     movl    %eax, -56(%ebp)
     91:     cmpl    $37, -56(%ebp)
     95:     je      8
     97:     movl    -56(%ebp), %eax
     9a:     jmp     831
     3de:    movl    %ebp, %esp
     3e0:    popl    %ebp
     3e1:    ret
     9f:     movl    8(%ebp), %ecx
     a2:     addl    $4, %ecx
     a5:     movl    %ecx, 8(%ebp)
     a8:     movl    8(%ebp), %edx
     ab:     movsbl  (%edx), %eax
     ae:     cmpl    $100, %eax
     b1:     je      10
     b3:     movl    $4294967294, %eax
     b8:     jmp     801
     bd:     movl    8(%ebp), %ecx
     c0:     movzbl  1(%ecx), %edx
     c4:     pushl   %edx
     c5:     calll   0
     External call to: to_byte
     ca:     addl    $4, %esp
     cd:     cmpl    $9, %eax
     d0:     je      10
     d2:     movl    $4294967293, %eax
     d7:     jmp     770
     dc:     movl    8(%ebp), %eax
     df:     movzbl  2(%eax), %ecx
     e3:     pushl   %ecx
     e4:     calll   0
     External call to: to_byte
     e9:     addl    $4, %esp
     ec:     movl    %eax, -40(%ebp)
     ef:     movl    -40(%ebp), %edx
     f2:     shll    %edx
     f4:     cmpl    $26, %edx
     f7:     je      10
     f9:     movl    $4294967292, %eax
     fe:     jmp     731
     103:    movl    8(%ebp), %eax
     106:    movzbl  3(%eax), %ecx
     10a:    pushl   %ecx
     10b:    calll   0
     External call to: to_byte
     110:    addl    $4, %esp
     113:    movl    %eax, -36(%ebp)
     116:    movl    -36(%ebp), %eax
     119:    addl    $1, %eax
     11c:    cltd
     11d:    subl    %edx, %eax
     11f:    sarl    %eax
     121:    cmpl    $7, %eax
     124:    je      10
     126:    movl    $4294967291, %eax
     12b:    jmp     686
     130:    movl    8(%ebp), %edx
     133:    movsbl  4(%edx), %eax
     137:    andl    $15, %eax
     13a:    cmpl    $1, %eax
     13d:    jne     27
     13f:    movl    8(%ebp), %ecx
     142:    movsbl  4(%ecx), %edx
     146:    andl    $240, %edx
     14c:    cmpl    $48, %edx
     14f:    jne     9
     151:    movl    $4294967292, -28(%ebp)
     158:    jmp     10
     164:    movl    8(%ebp), %eax
     167:    movsbl  5(%eax), %ecx
     16b:    andl    $15, %ecx
     16e:    movb    %cl, -29(%ebp)
     171:    movl    8(%ebp), %edx
     174:    movsbl  5(%edx), %eax
     178:    andl    $240, %eax
     17d:    movb    %al, -1(%ebp)
     180:    movzbl  -29(%ebp), %ecx
     184:    cmpl    $3, %ecx
     187:    jne     20
     189:    movzbl  -1(%ebp), %edx
     18d:    cmpl    $96, %edx
     190:    jne     11
     192:    movl    -28(%ebp), %eax
     195:    addl    $4, %eax
     198:    movl    %eax, -28(%ebp)
     19b:    jmp     9
     1a6:    movl    8(%ebp), %edx
     1a9:    movzbl  6(%edx), %eax
     1ad:    pushl   %eax
     1ae:    calll   0
     External call to: to_byte
     1b3:    addl    $4, %esp
     1b6:    movb    %al, -49(%ebp)
     1b9:    movl    8(%ebp), %ecx
     1bc:    movzbl  7(%ecx), %edx
     1c0:    pushl   %edx
     1c1:    calll   0
     External call to: to_byte
     1c6:    addl    $4, %esp
     1c9:    movzbl  -49(%ebp), %ecx
     1cd:    orl     %eax, %ecx
     1cf:    movb    %cl, -49(%ebp)
     1d2:    movzbl  -49(%ebp), %edx
     1d6:    notl    %edx
     1d8:    cmpl    $70, %edx
     1db:    jne     11
     1dd:    movl    -28(%ebp), %eax
     1e0:    subl    $1, %eax
     1e3:    movl    %eax, -28(%ebp)
     1e6:    jmp     11
     1f3:    cmpl    $0, -28(%ebp)
     1f7:    je      10
     1f9:    movl    $4294967289, %eax
     1fe:    jmp     475
     203:    pushl   $4
     205:    movl    8(%ebp), %eax
     208:    addl    $8, %eax
     20b:    pushl   %eax
     20c:    pushl   $0
     20e:    calll   0
     External call to: read_bytes
     213:    addl    $12, %esp
     216:    movw    %ax, -20(%ebp)
     21a:    movzwl  -20(%ebp), %ecx
     21e:    orl     $21845, %ecx
     224:    cmpl    $56663, %ecx
     22a:    jne     27
     22c:    movzwl  -20(%ebp), %edx
     230:    orl     $43690, %edx
     236:    cmpl    $65211, %edx
     23c:    jne     9
     23e:    movl    $43690, -28(%ebp)
     245:    jmp     7
     24e:    pushl   $8
     250:    movl    8(%ebp), %eax
     253:    addl    $12, %eax
     256:    pushl   %eax
     257:    pushl   $0
     259:    calll   0
     External call to: read_bytes
     25e:    addl    $12, %esp
     261:    movl    %eax, -24(%ebp)
     264:    movl    -24(%ebp), %ecx
     267:    xorl    $2760406685, %ecx
     26d:    movl    %ecx, -12(%ebp)
     270:    movl    -12(%ebp), %edx
     273:    shrl    $16, %edx
     276:    movl    %edx, -8(%ebp)
     279:    movl    -12(%ebp), %eax
     27c:    andl    $65535, %eax
     281:    movl    %eax, -16(%ebp)
     284:    cmpl    $20299, -8(%ebp)
     28b:    jne     17
     28d:    movl    -16(%ebp), %ecx
     290:    cmpl    -28(%ebp), %ecx
     293:    jne     9
     295:    movl    $0, -28(%ebp)
     29c:    jmp     7
     2a5:    pushl   $8
     2a7:    movl    8(%ebp), %edx
     2aa:    addl    $20, %edx
     2ad:    pushl   %edx
     2ae:    movl    -28(%ebp), %eax
     2b1:    pushl   %eax
     2b2:    calll   0
     External call to: read_bytes
     2b7:    addl    $12, %esp
     2ba:    movl    %eax, -48(%ebp)
     2bd:    movl    -48(%ebp), %ecx
     2c0:    subl    $3, %ecx
     2c3:    movl    %ecx, -48(%ebp)
     2c6:    movl    -48(%ebp), %edx
     2c9:    andl    $7, %edx
     2cc:    je      10
     2ce:    movl    $4294967275, %eax
     2d3:    jmp     262
     2d8:    movl    -48(%ebp), %eax
     2db:    subl    $2147483648, %eax
     2e0:    movl    %eax, -48(%ebp)
     2e3:    cmpl    $268435455, -48(%ebp)
     2ea:    jbe     10
     2ec:    movl    $4294967274, %eax
     2f1:    jmp     232
     2f6:    movl    -48(%ebp), %ecx
     2f9:    xorl    $13631488, %ecx
     2ff:    movl    %ecx, -48(%ebp)
     302:    movl    -48(%ebp), %edx
     305:    shrl    $4, %edx
     308:    movl    %edx, -48(%ebp)
     30b:    movl    -48(%ebp), %eax
     30e:    subl    $226, %eax
     313:    movl    %eax, -48(%ebp)
     316:    movl    -48(%ebp), %eax
     319:    xorl    %edx, %edx
     31b:    movl    $10000, %ecx
     320:    divl    %ecx
     322:    movl    %eax, -48(%ebp)
     325:    cmpl    $3, -48(%ebp)
     329:    je      8
     32b:    movl    -48(%ebp), %eax
     32e:    jmp     171
     333:    pushl   $4
     335:    movl    8(%ebp), %edx
     338:    addl    $28, %edx
     33b:    pushl   %edx
     33c:    movl    -28(%ebp), %eax
     33f:    pushl   %eax
     340:    calll   0
     External call to: read_bytes
     345:    addl    $12, %esp
     348:    movl    %eax, -44(%ebp)
     34b:    movl    8(%ebp), %ecx
     34e:    movsbl  28(%ecx), %edx
     352:    cmpl    $100, %edx
     355:    jne     23
     357:    movl    8(%ebp), %eax
     35a:    movsbl  29(%eax), %ecx
     35e:    cmpl    $100, %ecx
     361:    jne     11
     363:    movl    -28(%ebp), %edx
     366:    xorl    -44(%ebp), %edx
     369:    movl    %edx, -28(%ebp)
     36c:    jmp     109
     3db:    movl    -28(%ebp), %eax
     3de:    movl    %ebp, %esp
     3e0:    popl    %ebp
     3e1:    ret
     36e:    movl    8(%ebp), %eax
     371:    movsbl  28(%eax), %ecx
     375:    movl    8(%ebp), %edx
     378:    movsbl  29(%edx), %eax
     37c:    cmpl    %eax, %ecx
     37e:    jne     85
     380:    movl    8(%ebp), %ecx
     383:    movsbl  31(%ecx), %edx
     387:    movl    8(%ebp), %eax
     38a:    movsbl  30(%eax), %ecx
     38e:    subl    %ecx, %edx
     390:    movl    $15, %eax
     395:    subl    %edx, %eax
     397:    addl    -28(%ebp), %eax
     39a:    movl    %eax, -28(%ebp)
     39d:    movl    8(%ebp), %ecx
     3a0:    movzbl  28(%ecx), %edx
     3a4:    pushl   %edx
     3a5:    calll   0
     External call to: to_byte
     3aa:    addl    $4, %esp
     3ad:    movl    -28(%ebp), %ecx
     3b0:    subl    %eax, %ecx
     3b2:    movl    %ecx, -28(%ebp)
     3b5:    jne     28
     3b7:    movl    8(%ebp), %edx
     3ba:    movzbl  31(%edx), %eax
     3be:    pushl   %eax
     3bf:    calll   0
     External call to: to_byte
     3c4:    addl    $4, %esp
     3c7:    cmpl    $4, %eax
     3ca:    je      7
     3cc:    movl    $4294967264, -28(%ebp)
     3d3:    jmp     6
     3d3:    jmp     6
     3d5:    movl    -44(%ebp), %ecx
     3d8:    movl    %ecx, -28(%ebp)
     3db:    movl    -28(%ebp), %eax
     3de:    movl    %ebp, %esp
     3e0:    popl    %ebp
     3e1:    ret
     29e:    movl    $48351, -28(%ebp)
     2a5:    pushl   $8
     2a7:    movl    8(%ebp), %edx
     2aa:    addl    $20, %edx
     2ad:    pushl   %edx
     2ae:    movl    -28(%ebp), %eax
     2b1:    pushl   %eax
     2b2:    calll   0
     External call to: read_bytes
     2b7:    addl    $12, %esp
     2ba:    movl    %eax, -48(%ebp)
     2bd:    movl    -48(%ebp), %ecx
     2c0:    subl    $3, %ecx
     2c3:    movl    %ecx, -48(%ebp)
     2c6:    movl    -48(%ebp), %edx
     2c9:    andl    $7, %edx
     2cc:    je      10
     247:    movl    $48059, -28(%ebp)
     24e:    pushl   $8
     250:    movl    8(%ebp), %eax
     253:    addl    $12, %eax
     256:    pushl   %eax
     257:    pushl   $0
     259:    calll   0
     External call to: read_bytes
     25e:    addl    $12, %esp
     261:    movl    %eax, -24(%ebp)
     264:    movl    -24(%ebp), %ecx
     267:    xorl    $2760406685, %ecx
     26d:    movl    %ecx, -12(%ebp)
     270:    movl    -12(%ebp), %edx
     273:    shrl    $16, %edx
     276:    movl    %edx, -8(%ebp)
     279:    movl    -12(%ebp), %eax
     27c:    andl    $65535, %eax
     281:    movl    %eax, -16(%ebp)
     284:    cmpl    $20299, -8(%ebp)
     28b:    jne     17
     1e8:    movl    -28(%ebp), %edx
     1eb:    movl    -28(%ebp), %ecx
     1ee:    shll    %cl, %edx
     1f0:    movl    %edx, -28(%ebp)
     1f3:    cmpl    $0, -28(%ebp)
     1f7:    je      10
     19d:    movl    -28(%ebp), %ecx
     1a0:    addl    $5, %ecx
     1a3:    movl    %ecx, -28(%ebp)
     1a6:    movl    8(%ebp), %edx
     1a9:    movzbl  6(%edx), %eax
     1ad:    pushl   %eax
     1ae:    calll   0
     External call to: to_byte
     1b3:    addl    $4, %esp
     1b6:    movb    %al, -49(%ebp)
     1b9:    movl    8(%ebp), %ecx
     1bc:    movzbl  7(%ecx), %edx
     1c0:    pushl   %edx
     1c1:    calll   0
     External call to: to_byte
     1c6:    addl    $4, %esp
     1c9:    movzbl  -49(%ebp), %ecx
     1cd:    orl     %eax, %ecx
     1cf:    movb    %cl, -49(%ebp)
     1d2:    movzbl  -49(%ebp), %edx
     1d6:    notl    %processDataSection: section range (0, 7c)
     edx
     1d8:    cmpl    $70, %edx
     1db:    jne     11
     15a:    movl    $4294967290, %eax
     15f:    jmp     634
     getFunc: Function recovery complete for  func at 7c
     Warning: address 1 is not in a data section.
     Warning: address 2 is not in a data section.
     Warning: address 3 is not in a data section.
     Warning: address 4 is not in a data section.
     Warning: address 4 is not in a data section.
     Warning: address 5 is not in a data section.
     Warning: address 5 is not in a data section.
     Warning: address 6 is not in a data section.
     Warning: address 7 is not in a data section.
     Warning: address 6 is not in a data section.
     Warning: address 7 is not in a data section.
     Warning: address 1c is not in a data section.
     Warning: address 1d is not in a data section.
     Warning: address 1c is not in a data section.
     Warning: address 1d is not in a data section.
     Warning: address 1f is not in a data section.
     Warning: address 1e is not in a data section.
     Warning: address 1c is not in a data section.
     Warning: address 1f is not in a data section.
     Adding entry point: sailboat
     inserting global data section named data_0x0
     sailboat_run.c
     a winner is you!

## demo_dll_1

Translates a compiled DLL that calls the Windows MessageBox API and displays a message box that says "Simple DLL"

     C:\dev\llvm-new\mc-sema\tests>demo_dll_1
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_dll_1.exp
     demo_dll_1.c
        Creating library demo_dll_1.lib and object demo_dll_1.exp
     processDataSection: section range (1000a000, 1000d200)
     processDataSection: section range (1000e000, 1000f000)
     processDataSection: section range (10010000, 10010a00)
     processDataSection: section range (10011000, 10011a00)
     getFunc: Starting at 0x10001005
     10001005:       jmp     38
     10001030:       pushl   %ebp
     10001031:       movl    %esp, %ebp
     10001033:       pushl   $0
     10001035:       pushl   $268492800
     1000103a:       pushl   $268492816
     1000103f:       pushl   $0
     10001041:       calll   *268501772
     Calling symbol: MessageBoxA
     10001047:       movl    $1, %eax
     1000104c:       popl    %ebp
     1000104d:       ret
     getFunc: Function recovery complete for  func at 10001005
     Adding entry point: demo_dll_1_driver
     inserting global data section named data_0x1000a000
     inserting global data section named data_0x1000e000
     inserting global data section named data_0x10010000
     inserting global data section named data_0x10011000
     demo_driver_dll_1.c
     About to do msgbox...

## demo_dll_2

Translates a DLL that creates a new thread that displays a message box. this tests identifying data references to code and creating callbacks that can be used by external APIs, such as CreateThread.

     C:\dev\llvm-new\mc-sema\tests>demo_dll_2
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_dll_2.exp
     demo_dll_2.c
     Microsoft (R) Incremental Linker Version 10.00.40219.01
     Copyright (C) Microsoft Corporation.  All rights reserved.
     
        Creating library demo_dll_2.lib and object demo_dll_2.exp
     getFunc: Starting at 0x10001030
     10001030:       subl    $24, %esp
     10001033:       movl    268447768, %edx
     10001039:       movl    268447760, %eax
     1000103e:       movl    268447764, %ecx
     10001044:       movl    %eax, 4(%esp)
     10001048:       movl    268447772, %eax
     1000104d:       movl    %edx, 12(%esp)
     10001051:       leal    (%esp), %edx
     10001054:       pushl   %edx
     10001055:       pushl   $0
     10001057:       movl    %eax, 24(%esp)
     1000105b:       leal    12(%esp), %eax
     1000105f:       pushl   %eax
     10001060:       pushl   $268439568
     10001065:       movl    %ecx, 24(%esp)
     10001069:       movb    268447776, %cl
     1000106f:       pushl   $0
     10001071:       pushl   $processDataSection: section range (10002000, 10002200)
     processDataSection: section range (10003000, 10003200)
     processDataSection: section range (10004000, 10004200)
     0
     10001073:       movb    %cl, 44(%esp)
     10001077:       calll   *268443648
     Calling symbol: CreateThread
     1000107d:       addl    $24, %esp
     10001080:       ret
     getFunc: Function recovery complete for  func at 10001030
     getFunc: Starting at 0x10001010
     10001010:       movl    4(%esp), %eax
     10001014:       pushl   $0
     10001016:       pushl   %eax
     10001017:       pushl   $268447744
     1000101c:       pushl   $0
     1000101e:       calll   *268443656
     Calling symbol: MessageBoxA
     10001024:       ret     $4
     getFunc: Function recovery complete for  func at 10001010
     Adding entry point: demo_dll_2_driver
     inserting global data section named data_0x10002000
     inserting global data section named data_0x10003000
     inserting global data section named data_0x10004000
     demo_driver_dll_2.c
     win32_callback_adapter.c
     Generating Code...
     About to do msgbox via thread...
     Created thead: 00000038
     Waiting for 10 sec for msgbox...
     Wait succeeded!


## demo_dll_3

This demo translates a DLL that calls several functions and links to many external APIs. This DLL is a working network server that listens on a port and echos its input back out the socket. The server is spawned in its own thread. 

     C:\dev\llvm-new\mc-sema\tests>demo_dll_3
     Could Not Find C:\dev\llvm-new\mc-sema\tests\demo_dll_3.exp
     demo_dll_3.c
     Microsoft (R) Incremental Linker Version 10.00.40219.01
     Copyright (C) Microsoft Corporation.  All rights reserved.
     
        Creating library demo_dll_3.lib and object demo_dll_3.exp
     getFunc: Starting at 0x100012b0
     100012b0:       pushl   %ebp
     100012b1:       movl    %esp, %ebp
     100012b3:       subl    $416, %esp
     100012b9:       leal    -408(%ebp), %eax
     100012bf:       pushl   %eax
     100012c0:       pushl   $514
     100012c5:       calll   *268443692
     Calling symbol: WSAStartup
     100012cb:       movl    %eax, -416(%ebp)
     100012d1:       cmpl    $0, -416(%ebp)
     100012d8:       je      4
     100012da:       xorl    %eax, %eax
     100012dc:       jmp     48
     1000130e:       movl    %ebp, %esp
     10001310:       popl    %ebp
     10001311:       ret
     100012de:       leal    -4(%ebp), %ecx
     100012e1:       pushl   %ecx
     100012e2:       pushl   $0
     100012e4:       pushl   $0
     100012e6:       pushl   $268439568
     100012eb:       pushl   $0
     100012ed:       pushl   $0
     100012ef:       calll   *268443648
     Calling symbol: CreateThread
     100012f5:       movl    %eax, -412(%ebp)
     100012fb:       cmpl    $0, -412(%ebp)
     10001302:       je      8
     10001304:       movl    -412(%ebp), %eax
     1000130a:       jmp     2
     1000130c:       xorl    %eax, %eax
     1000130e:       movl    %ebp, %esp
     10001310:       popl    %ebp
     10001311:       ret
     getFunc: Function recovery complete for  func at 100012b0
     getFunc: Starting at 0x10001010
     10001010:       pushl   %ebp
     10001011:       movl    %esp, %ebp
     10001013:       subl    $572, %esp
     10001019:       movl    $4294967295, -8(%ebp)
     10001020:       movl    $4294967295, -4(%ebp)
     10001027:       movl    $0, -572(%ebp)
     10001031:       movl    $512, -12(%ebp)
     10001038:       movl    $2, -564(%ebp)
     10001042:       movl    $1, -560(%ebp)
     1000104c:       movl    $6, -556(%ebp)
     10001056:       movl    $1, -568(%ebp)
     10001060:       pushl   $268447744
     10001065:       pushl   $268447752
     1000106a:       calll   675
     1000106f:       addl    $8, %esp
     10001072:       leal    -572(%ebp), %eax
     10001078:       pushl   %eax
     10001079:       leal    -568(%ebp), %ecx
     1000107f:       pushl   %ecx
     10001080:       pushl   $268447776
     10001085:       pushl   $0
     10001087:       calll   *268443688
     Calling symbol: getaddrinfo
     1000108d:       movl    %eax, -532(%ebp)
     10001093:       cmpl    $0, -532(%ebp)
     1000109a:       je      16
     1000109c:       calll   *268443684
     Calling symbol: WSACleanup
     100010a2:       movl    $1, %eax
     100010a7:       jmp     507
     100012a7:       movl    %ebp, %esp
     100012a9:       popl    %ebp
     100012aa:       ret     $4
     100010ac:       movl    -572(%ebp), %edx
     100010b2:       movl    12(%edx), %eax
     100010b5:       pushl   %eax
     100010b6:       movl    -572(%ebp), %ecx
     100010bc:       movl    8(%ecx), %edx
     100010bf:       pushl   %edx
     100010c0:       movl    -572(%ebp), %eax
     100010c6:       movl    4(%eax), %ecx
     100010c9:       pushl   %ecx
     100010ca:       calll   *268443704
     Calling symbol: socket
     100010d0:       movl    %eax, -8(%ebp)
     100010d3:       cmpl    $-1, -8(%ebp)
     100010d7:       jne     29
     100010d9:       movl    -572(%ebp), %edx
     100010df:       pushl   %edx
     100010e0:       calll   *268443676
     Calling symbol: freeaddrinfo
     100010e6:       calll   *268443684
     Calling symbol: WSACleanup
     100010ec:       movl    $1, %eax
     100010f1:       jmp     433
     100010f6:       movl    -572(%ebp), %eax
     100010fc:       movl    16(%eax), %ecx
     100010ff:       pushl   %ecx
     10001100:       movl    -572(%ebp), %edx
     10001106:       movl    24(%edx), %eax
     10001109:       pushl   %eax
     1000110a:       movl    -8(%ebp), %ecx
     1000110d:       pushl   %ecx
     1000110e:       calll   *268443672
     Calling symbol: bind
     10001114:       movl    %eax, -532(%ebp)
     1000111a:       cmpl    $-1, -532(%ebp)
     10001121:       jne     39
     10001123:       movl    -572(%ebp), %edx
     10001129:       pushl   %edx
     1000112a:       calll   *268443676
     Calling symbol: freeaddrinfo
     10001130:       movl    -8(%ebp), %eax
     10001133:       pushl   %eax
     10001134:       calll   *268443668
     Calling symbol: closesocket
     1000113a:       calll   *268443684
     Calling symbol: WSACleanup
     10001140:       movl    $1, %eax
     10001145:       jmp     349
     1000114a:       movl    -572(%ebp), %ecx
     10001150:       pushl   %ecx
     10001151:       calll   *268443676
     Calling symbol: freeaddrinfo
     10001157:       pushl   $2147483647
     1000115c:       movl    -8(%ebp), %edx
     1000115f:       pushl   %edx
     10001160:       calll   *268443664
     Calling symbol: listen
     10001166:       movl    %eax, -532(%ebp)
     1000116c:       cmpl    $-1, -532(%ebp)
     10001173:       jne     26
     10001175:       movl    -8(%ebp), %eax
     10001178:       pushl   %eax
     10001179:       calll   *268443668
     Calling symbol: closesocket
     1000117f:       calll   *268443684
     Calling symbol: WSACleanup
     10001185:       movl    $1, %eax
     1000118a:       jmp     280
     1000118f:       pushl   $0
     10001191:       pushl   $0
     10001193:       movl    -8(%ebp), %ecx
     10001196:       pushl   %ecx
     10001197:       calll   *268443680
     Calling symbol: accept
     1000119d:       movl    %eax, -4(%ebp)
     100011a0:       cmpl    $-1, -4(%ebp)
     100011a4:       jne     26
     100011a6:       movl    -8(%ebp), %edx
     100011a9:       pushl   %edx
     100011aa:       calll   *268443668
     Calling symbol: closesocket
     100011b0:       calll   *268443684
     Calling symbol: WSACleanup
     100011b6:       movl    $1, %eax
     100011bb:       jmp     231
     100011c0:       movl    -8(%ebp), %eax
     100011c3:       pushl   %eax
     100011c4:       calll   *268443668
     Calling symbol: closesocket
     100011ca:       pushl   $0
     100011cc:       movl    -12(%ebp), %ecx
     100011cf:       pushl   %ecx
     100011d0:       leal    -528(%ebp), %edx
     100011d6:       pushl   %edx
     100011d7:       movl    -4(%ebp), %eax
     100011da:       pushl   %eax
     100011db:       calll   *268443696
     Calling symbol: recv
     100011e1:       movl    %eax, -532(%ebp)
     100011e7:       cmpl    $0, -532(%ebp)
     100011ee:       jle     66
     100011f0:       pushl   $0
     100011f2:       movl    -532(%ebp), %ecx
     100011f8:       pushl   %ecx
     100011f9:       leal    -528(%ebp), %edx
     100011ff:       pushl   %edx
     10001200:       movl    -4(%ebp), %eax
     10001203:       pushl   %eax
     10001204:       calll   *268443700
     Calling symbol: send
     1000120a:       movl    %eax, -536(%ebp)
     10001210:       cmpl    $-1, -536(%ebp)
     10001217:       jne     23
     10001219:       movl    -4(%ebp), %ecx
     1000121c:       pushl   %ecx
     1000121d:       calll   *268443668
     Calling symbol: closesocket
     10001223:       calll   *268443684
     Calling symbol: WSACleanup
     10001229:       movl    $1, %eax
     1000122e:       jmp     119
     10001230:       jmp     36
     10001256:       cmpl    $0, -532(%ebp)
     1000125d:       jg      -153
     10001263:       pushl   $1
     10001265:       movl    -4(%ebp), %eax
     10001268:       pushl   %eax
     10001269:       calll   *268443708
     Calling symbol: shutdown
     1000126f:       movl    %eax, -532(%ebp)
     10001275:       cmpl    $-1, -532(%ebp)
     1000127c:       jne     23
     1000127e:       movl    -4(%ebp), %ecx
     10001281:       pushl   %ecx
     10001282:       calll   *268443668
     Calling symbol: closesocket
     10001288:       calll   *268443684
     Calling symbol: WSACleanup
     1000128e:       movl    $1, %eax
     10001293:       jmp     18
     10001295:       movl    -4(%ebp), %edx
     10001298:       pushl   %edx
     10001299:       calll   *268443668
     Calling symbol: closesocket
     1000129f:       calll   *268443684
     Calling symbol: WSACleanup
     100012a5:       xorl    %eax, %eax
     100012a7:       movl    %ebp, %esp
     100012a9:       popl    %ebp
     100012aa:       ret     $4
     100011ca:       pushl   $0
     100011cc:       movl    -12(%ebp), %ecx
     100011cf:       pushl   %ecx
     100011d0:       leal    -528(%ebp), %edx
     100011d6:       pushl   %edx
     100011d7:       movl    -4(%ebp), %eax
     100011da:       pushl   %eax
     100011db:       calll   *268443696
     Calling symbol: recv
     100011e1:       movl    %eax, -532(%ebp)
     100011e7:       cmpl    $0, -532(%ebp)
     100011ee:       jle     66
     10001232:       cmpl    $0, -532(%ebp)
     10001239:       jne     4
     1000123b:       jmp     38
     1000123f:       movl    -4(%ebp), %edx
     10001242:       pushl   %edx
     10001243:       calll   *268443668
     Calling symbol: closesocket
     10001249:       calll   *268443684
     Calling symbol: WSACleanup
     1000124f:       movl    $1, %eaxprocessDataSection: section range (10002000, 10002200)
     processDataSection: section range (10003000, 10003200)
     processDataSection: section range (10004000, 10004200)
     
     10001254:       jmp     81
     getFunc: Function recovery complete for  func at 10001010
     Warning: address c is not in a data section.
     Warning: address 8 is not in a data section.
     Warning: address 4 is not in a data section.
     Warning: address 10 is not in a data section.
     Warning: address 18 is not in a data section.
     Adding entry point: demo_dll_3_driver
     inserting global data section named data_0x10002000
     inserting global data section named data_0x10003000
     inserting global data section named data_0x10004000
     demo_driver_dll_3.c
     win32_callback_adapter.c
     Generating Code...
     About to create server thread...
     Created thead: 00000038
     Waiting for server thread to terminate...
     Listening on port: 1337

## demo_dll_4

Translate a DLL that has multithreading, call by register, and call by memory. The DLL displays two message boxes: "I'm called via memory!" and "I'm called via register!". 

    C:\git\llvm-lift\mc-sema\tests>demo_dll_4.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_dll_4.exp
    cl : Command line warning D9035 : option 'Og' has been deprecated and will be removed in a
    future release
    demo_dll_4.c
    Microsoft (R) Incremental Linker Version 10.00.40219.01
    Copyright (C) Microsoft Corporation.  All rights reserved.
    
       Creating library demo_dll_4.lib and object demo_dll_4.exp
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --entry-symbol call_ptrs --std-defs ..\\std_defs\\std_defs.txt --output demo_dll_4.cfg', 'demo_dll_4.dll']
    Already have driver for: call_ptrs
    inserting global data section named data_0x1000200c
    inserting global data section named data_0x10003000
    makeCallbackForLocalFunction: Adding Callbacks to Module!
    Adding entry point: demo_dll_4_driver
    demo_driver_dll_4.c
    About to call a function pointer...
    Function returned: 31337

## demo_dll_5

Create global data in a DLL that is modified and returned outside of the DLL scope.

    C:\git\llvm-lift\mc-sema\tests>demo_dll_5.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_dll_5.exp
    cl : Command line warning D9035 : option 'Og' has been deprecated and will be removed in a
    future release
    demo_dll_5.c
    Microsoft (R) Incremental Linker Version 10.00.40219.01
    Copyright (C) Microsoft Corporation.  All rights reserved.
    
       Creating library demo_dll_5.lib and object demo_dll_5.exp
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --entry-symbol who_is_spartacus who_is_spartacus2get_response --std-defs ..\\std_defs\\std_defs.txt --output demo_dll_5.cfg', 'demo_dll_5.dll']
    Already have driver for: who_is_spartacus
    Already have driver for: who_is_spartacus2
    Already have driver for: get_response
    inserting global data section named data_0x10002008
    inserting global data section named data_0x10003000
    Adding entry point: d_who_spartacus
    Adding entry point: d_who_spartacus2
    Adding entry point: d_get_response
    demo_driver_dll_5.c
    LINK : warning LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs; use /NODEFAUL
    TLIB:library
    Who is Spartacus?
    Answer: I am Spartacus
    ... wait ...
    Another Answer: No, I am Spartacus!

## demo_dll_6

Test data exports from a translated DLL.

    C:\git\llvm-lift\mc-sema\tests>demo_dll_6.bat
    Could Not Find C:\git\llvm-lift\mc-sema\tests\demo_dll_6.exp
    cl : Command line warning D9035 : option 'Og' has been deprecated and will be removed in a
    future release
    demo_dll_6_data.c
    Microsoft (R) Incremental Linker Version 10.00.40219.01
    Copyright (C) Microsoft Corporation.  All rights reserved.
    
       Creating library demo_dll_6_data.lib and object demo_dll_6_data.exp
    cl : Command line warning D9035 : option 'Og' has been deprecated and will be removed in a
    future release
    demo_dll_6.c
    Microsoft (R) Incremental Linker Version 10.00.40219.01
    Copyright (C) Microsoft Corporation.  All rights reserved.
    
       Creating library demo_dll_6.lib and object demo_dll_6.exp
    Using IDA to recover CFG
    Executing: ['C:\\Program Files\\IDA 6.5\\idaq.exe', '-B', '-S..\\..\\build\\mc-sema\\bin_descend\\Debug\\get_cfg.py --batch --debug --entry-symbol get_value --std-defs ..\\std_defs\\std_defs.txt demo_6_defs.txt --output demo_dll_6.cfg', 'demo_dll_6.dll']
    Already have driver for: get_value
    inserting global data section named data_0x10002008
    Adding entry point: d_get_value
    demo_driver_dll_6.c
    LINK : warning LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs; use /NODEFAUL
    TLIB:library
    This should print 42: 42 [2a]

