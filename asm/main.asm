section .text                   ;section declaration
    global  _start              ;loader. They conventionally recognize _start as their

_start:
    push rbp
    mov     rdi,0x1
    mov     rsi,msg
    mov     rdx,len
    mov     rax,1
    syscall

   mov      rax, 60
   syscall

section .data                   ;section declaration
msg db      "Hello, world!",0xa ;our dear string
len equ     $ - msg             ;length of our dear string
