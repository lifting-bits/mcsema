typedef struct _regs {
    unsigned long EAX;
     unsigned long    EBX;
     unsigned long    ECX;
   unsigned long      EDX;
   unsigned long      ESI;
   unsigned long      EDI;
   unsigned long      ESP;
    unsigned long     EBP;
} regs;

extern void sub_1(regs *);

void doRet(unsigned long addr, regs *r, unsigned long myFrame) {

    __asm {
        mov edi, myFrame
        //this skips us back up to where our doCall method took us
        add edi, 12
        mov eax, addr
        mov esp, edi
        //need to unconditionally branch to 'addr' after restoring 
        //registers from the stack and doing other cleanup
        pop ebp
        jmp eax
    }
    return;
}

int doCallSub_1(void) {
    regs            rState = {0};
    unsigned long   stack[4096*10];

    //set up the stack 
    rState.ESP = (unsigned long) &stack[4096*9];

    __asm {
        lea eax, stack
        mov  ebx, 0x9000 //it is actually just at 9000
        mov  ecx, done
        mov  [eax+ebx*4], ecx
        lea eax, rState
        push ebp
        push eax
        call sub_1
done:
        mov edi, edi 
    }

    return rState.EAX;
}

int main(int argc, char *argv[]) {

    int k = doCallSub_1();

    printf("0x%X\n", k);

    return 0;
}
