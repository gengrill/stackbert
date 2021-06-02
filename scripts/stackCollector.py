#!/home/chinmay/Projects/scratch/var/bin/python

import sys
sys.path.append("/home/chinmay/Projects/scratch/var/lib/python3.8/site-packages")

import rzpipe
import gdb
import pdb

gdb.execute("set pagination off")

fileName = gdb.current_progspace().filename

# TODO: Replace all instances of esp and eip with rsp and rip if target is 64 bits

pipe = rzpipe.open(fileName)
pipe.cmd("aa")

address_map = {}

allFuncs = pipe.cmdj("aflj")
for func in allFuncs:
    funcName = func['name']
    if ("sym." in funcName and "sym.imp." not in funcName) or func['name'] == "main":
        addr = func["offset"]
        address_map[addr] = {}
        address_map[addr]["name"] = funcName
        address_map[addr]["max"] = 0
        gdb.execute(f"break *{hex(addr)}")
        exitAddrs = [int(x, 16) for x in pipe.cmd(f"afbr @ {funcName}").split("\n")[:-1]]
        address_map[addr]['exitAddrs'] = []
        for exitAddr in exitAddrs:
            address_map[addr]['exitAddrs'].append(exitAddr)
            gdb.execute(f"break *{hex(exitAddr)}")

def get_reg_value(reg):
    return int(gdb.parse_and_eval(reg))

call_stack = []

gdb.execute("run")
r_eip = get_reg_value("$eip")
global_entry = r_eip

class ESP_Watchpoint(gdb.Breakpoint):
    def stop(self):
        global call_stack

        curr_esp = get_reg_value("$esp") 
        eip_entry, esp_entry, func_name, max_diff = call_stack.pop()
        curr_diff = esp_entry - curr_esp
        max_diff = max(curr_diff, max_diff)
        call_stack.append((eip_entry, esp_entry, func_name, max_diff))

        return False

esp_watcher = ESP_Watchpoint("$esp", gdb.BP_WATCHPOINT, gdb.WP_WRITE)

while True:
    r_eip = get_reg_value("$eip")
    if r_eip in address_map:
        r_esp = get_reg_value("$esp")
        call_stack.append((r_eip, r_esp, address_map[r_eip]["name"], 0))
        global_entry = r_eip
    elif r_eip in address_map[global_entry]['exitAddrs']:
        eip_entry, final_esp, _, max_diff = call_stack.pop()
        address_map[eip_entry]["max"] = max(max_diff, address_map[eip_entry]["max"])
        if len(call_stack) == 0:
            break
        global_entry, _, _, _ = call_stack[-1]
    else:
        print("[-] Something went wrong")
        
    gdb.execute("continue")

for addr in address_map:
    print(f"{address_map[addr]['name']} : {address_map[addr]['max']}")
gdb.execute("quit")
