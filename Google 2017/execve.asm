global _start

_start:
    lea rsi, [rsp + 8] ; argv and envp null
    xor rdx, rdx
    lea rdi, [rsp + 32] ; string
    push 0x3b       ; execve
    pop rax          
    syscall         ; make the call