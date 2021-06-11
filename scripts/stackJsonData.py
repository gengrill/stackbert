#!/home/chinmay/Projects/scratch/var/bin/python

import sys
sys.path.append("/home/chinmay/Projects/scratch/var/lib/python3.8/site-packages")

import json
import rzpipe
import pdb
import os

import argparse

parser = argparse.ArgumentParser(description='Collect data for pin')
parser.add_argument('--file', metavar='F', 
        type=str, help='Input binary path')
parser.add_argument('--output', metavar='O', 
        type=str, help='Output file path')

args = parser.parse_args()

file_path = args.file
file_name = file_path.split(os.sep)[-1]
pipe = rzpipe.open(file_path)
pipe.cmd("aa")

address_map = {}

# def get_exit_addrs(func_name):
#     exit_addrs = []
#     fn_info = pipe.cmdj(f"afbj @ {func_name}")
#     for bb in fn_info:
#         if bb["outputs"] == 0:  # Check if outputs are 0
#             addr = bb["addr"]
#             bb_info = pipe.cmdj(f"pdbj @ {addr}")
#             exit_addrs.append(bb_info[-1]["offset"])
#     return exit_addrs

with open(args.output, "w") as fp:
    all_funcs = pipe.cmdj("aflj")
    for func in all_funcs:
        func_name = func['name']
        if "sym." in func_name or func_name == "main":
            if "sym.imp" in func_name or "sym._" in func_name:
                continue
            fp.write("0 " + str(func["offset"]) + "\n")
            exit_addrs = [int(x, 16) for x in pipe.cmd(f"afbr @ {func_name}").split("\n")[:-1]]
            # exit_addrs = get_exit_addrs(func_name)
            for exit_addr in exit_addrs:
                fp.write("1 " + str(exit_addr) + "\n")
            all_instrs = pipe.cmdj(f"pdfj @ {func_name}")
            for instr in all_instrs["ops"]:
                fp.write("2 " + str(instr["offset"]) + "\n")
            fp.write("3 " + func_name + "\n")
