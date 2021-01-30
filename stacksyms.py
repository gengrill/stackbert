import os
import logging
logging.basicConfig(format='%(asctime)s %(levelname)s:%(funcName)s:%(message)s',   \
                    datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)

# requires pyelftools and pygdbmi, install with "pip3 install pyelftools pygdbmi"
from pygdbmi.gdbcontroller import GdbController
from elftools.elf.elffile import ELFFile

# from https://github.com/Vector35/dwarf_import
from dwarf_import.model.module import Module
from dwarf_import.model.elements import Component, LocationType
from dwarf_import.io.dwarf_expr import ExprEval, LocExprParser
#from dwarf_import.io.dwarf_import import create_module_from_ELF_DWARF_file
from dwarf_import.io.dwarf_import import DWARFDB, DWARFImporter
from dwarf_import.io.dwarf_import import place_component_in_module_tree

# dwarf_import has:
#   (1) the io classes which deal with ELF/DWARF stuff,
#   (2) the model classes which are more general, high-level data containers
#   (3) the parsers themselves which are stateful because DWARF contains stack machines
# We may need all of the above to get what we want, because some things (like lineprograms)
# are not implemented in that library (or any other library I looked at).

def parseDirectory(dirPath):
    fmap = {fname : parseELF(dirPath + os.sep + fname) for fname in next(os.walk(dirPath))[2]}
    logging.info(f"Found {sum(map(len,functions))} functions total in {len(functions)} files.")
    return fmap

def parseELF(filepath):
    '''Returns a list of functions for this file (if the file contains debug info)'''
    logging.info(f"Trying to parse {filepath} as ELF")
    elf = ELFFile(open(filepath, 'rb'))
    module, importer = parseDWARF(elf)
    functions = getFunctions(module)  # a list of model.elements.Function type objects
    logging.info(f"Found {len(functions)} functions.")
    return functions

# 1: walk directory -> foreach file
# 2:   parse ELF & DWARF
#        get list of functions along with their parsed data model
# 3:   collect disas & initial frame layout

def getFunctions(module):
    '''Returns a list of dwarf_import.model.elements.Function objects.'''
    functions = []
    for m in module.children():
        if type(m) == Module:
            functions += getFunctions(m)
        if type(m) == Component:
            logging.debug(f"Found {len(m.functions)} function definitions in component {m.name}")
            functions += m.functions
    return functions

def collectDisassembly(functions):
    #TODO
    logging.info("Trying to collect function bodies via GDB..")
    disasQueries = ['disas /r ' + func.name for func in functions]
    gdbOut = staticGDB(debugFilepath, functions, disasQueries)
    for disas, func in zip(gdbOut, functions):
        func.disas = [tuple(line.strip().split('\\t')) for line in disas[1:-1]]
    return functions

def generateDebugLabel(func):
#    TODO
    stackVars = filter(func.variables, isOnStack)
#    return [
#                print(hex(loc.begin) + " to " + hex(loc.end) + ": " \
#                      + str(loc.type)[13:] + str(loc.expr))


def parseDWARF(elf):
#    return create_module_from_ELF_DWARF_file(debugFilepath)
# we need the line program to get basic blocks (or at least the first one)
    if elf.has_dwarf_info():
        logging.info("File has debug info..")
        module = Module() # this is high-level the data model (no deps on ELF/DWARF types etc)
        dwarfDB = DWARFDB(elf) # this the io data class for parsing
        importer = DWARFImporter(dwarfDB, dict()) # has state after parsing
        for component in importer.import_components():
            place_component_in_module_tree(module, component)
        return module, importer
    logging.warn("File does not contain debugging information!")
    return None

def isOnStack(variable):
    # TODO This should probably be named "isOnStackInInitialFrame" or sth like that.
    # The goal here is to determine if a dwarf_import.model.elements.Variable is on stack or not
    # when we enter the first frame of the function.. it's not trivial, we have to determine:
    # (1) if there is a location at all (could have been optimized out)
    # (2) if so, whether its _first_ reported location is in the range
    #     of the first basic block of the function.. otherwise its
    #     creation is dependent on the function's control flow.
    # (3) if so, whether the location isn't actually a register.
    # (4) if so, return the offset from frame base along with its size
    if len(variable.locations)==0:
        return False
    if variable.type == LocationType.STATIC_GLOBAL:
        return not isInReg(variable)
    return False

'''
for func in functions:
    print('////////////////////////')
    print(func.name, func.frame_base)
    for lvar in func.variables:
        print(lvar.name, lvar.type, "(bytesize = %d)"%lvar.type.byte_size)
        for loc in lvar.locations:
            print(hex(loc.begin) + " to " + hex(loc.end) + ": " \
#            + str(loc.type)[13:]
            + str(loc.expr))
        print('')
'''

def isInReg(variable): # TODO should be named "isInRegInInitialFrame"
    initFrameLoc = variable.locations[0]
    if len(initFrameLoc) == 1:
        return True # TODO: implement the check
    return False

def generateLabels(function):
    return list(map(lambda x : x[1], generateDebugLabel(function)))

def collectLocals(gdbOutput, functions):
    symbol, size, off = None, None, None
    for line in gdbOutput[1:]:
        if line.find('Symbol') != -1:
            symbol = line.split(' ')[1]
            size, off = None, None
            logging.info("Found scope info for symbol %s" % symbol)
        elif line.find('length') != -1:
            size = int(line[line.find('length') + 6 : -3])
            funcDict[symbol]['size']   = size
            logging.info("Has size info (%d bytes)!" % size)
        elif line.find('DW_OP_fbreg') != -1:
            if 'offset' not in funcDict[symbol]:
                funcDict[symbol]['offset'] = []
            off = line.split(' ')[6::]
            funcDict[symbol]['offset'] += [(off[0], int(off[1][0:-2]))]
            logging.info("Has stack location!")
        if symbol != None and symbol not in funcDict:
            logging.warning("Symbol '%s' reported in function scope by GDB but not by PyELFTools." % symbol)
            return

# using GDB for two reasons: (1) it gives us both disassembly and local variables, and (2) everyone has it
def staticGDB(gdbmi, filepaths, functions, queries):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    if type(filepaths) == str: # just one path
        logging.info("Loading file %s statically in GDB." % filepaths)
        
        result = [gdbmi.write('-file-exec-and-symbols ' + filepaths)]
        for q in queries:
            result += [[msg['payload'] for msg in gdbmi.write(q) if msg['type']=='console']]
        gdbmi.exit()
        return result[1:] # skip meta output
    elif type(filepaths) == list:
        logging.info("Batch loading several files statically in GDB..")
        gdbmi  = GdbController()
        result = []
        for fpath in filepaths:
            fileResult = [gdbmi.write('-file-exec-and-symbols ' + fpath)]
            for q in queries:
                fileResult += [[msg['payload'] for msg in gdbmi.write(q) if msg['type']=='console']]
            result += fileResult[1:]
        gdbmi.exit()
        return result
