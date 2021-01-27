import logging
logging.basicConfig(format='%(asctime)s %(levelname)s:%(funcName)s:%(message)s',   \
                    datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)

# requires pyelftools and pygdbmi, install with "pip3 install pyelftools pygdbmi"
from pygdbmi.gdbcontroller import GdbController
from elftools.elf.elffile import ELFFile

# from https://github.com/Vector35/dwarf_import
from dwarf_import.model.module import Module
from dwarf_import.model.elements import LocationType
from dwarf_import.io.dwarf_expr import ExprEval, LocExprParser
#from dwarf_import.io.dwarf_import import create_module_from_ELF_DWARF_file
from dwarf_import.io.dwarf_import import DWARFDB, DWARFImporter
from dwarf_import.io.dwarf_import import place_component_in_module_tree

def parseFunctions(debugFilepath):
    module, importer = parseDWARF(debugFilepath)
    firstUnit = module.components[0]
    functions = firstUnit.functions
    disasQueries = ['disas /r ' + func.name for func in functions]
    gdbOut = staticGDB(debugFilepath, functions, disasQueries)
    for disas, func in zip(gdbOut, functions):
        func.disas = [tuple(line.strip().split('\\t')) for line in disas[1:-1]]
    return functions

def parseDWARF(debugFilepath):
#    return create_module_from_ELF_DWARF_file(debugFilepath)
# we need the line program to get basic blocks (or at least the first one)
    elf = ELFFile(open(debugFilepath, 'rb'))
    if elf.has_dwarf_info():
        module = Module()
        dwarfDB = DWARFDB(elf)
        importer = DWARFImporter(dwarfDB, dict())
        for component in importer.import_components():
            place_component_in_module_tree(module, component)
        return module, importer
    return None

'''
def generateDebugLabel(func):
    stackVars = filter(func.variables, isOnStack)
    return [
#                print(hex(loc.begin) + " to " + hex(loc.end) + ": " \
#                      + str(loc.type)[13:] + str(loc.expr))
'''

def tokenize(features): # a token is two bytes
    return [[int(x[i:i+2], 16) for i in range(0,len(x),2)] for x in features]

def generateFeatures(function): # a feature is an instruction (128 bytes max)
    return tokenize(map(lambda t : t[1].replace(' ', ''), function.disas))

def generatePositionalEncodings(function): # code addresses
    return list(map(lambda t : t[0][0:18], function.disas))


def isOnStack(variable): # TODO should be named "isOnStackInInitialFrame"
    # it's not trivial.. we have to determine if:
    # (1) there is a location at all (could have been optimized out)
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

def collectLocals(gdbOutput, funcDict):
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

def staticGDB(debugFilepath, functions, queries):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    logging.info("Loading file %s statically in GDB." % debugFilepath)
    gdbmi  = GdbController()
    result = [gdbmi.write('file ' + debugFilepath)]
    for q in queries:
        result += [[msg['payload'] for msg in gdbmi.write(q) if msg['type']=='console']]
    gdbmi.exit()
    return result[1:]

