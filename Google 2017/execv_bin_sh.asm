global _start

_start:
    xor rsi, rsi ; argv and envp null
    xor rdx, rdx
    mov rdi,0x00736c2f6e69622f ; \x0hs/nib/
    push rdi        
    push rsp       
    pop rdi         ; pointer to arguments
    push 0x3b       ; execve
    pop rax          
    syscall         ; make the call