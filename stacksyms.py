import logging
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s',   \
                    datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)

# requires pyelftools and pygdbmi, install with "pip3 install pyelftools pygdbmi"
from pygdbmi.gdbcontroller import GdbController
from elftools.elf.elffile import ELFFile

# from https://github.com/Vector35/dwarf_import
from dwarf_import.io.dwarf_expr import ExprEval, LocExprParser
from dwarf_import.io.dwarf_import import create_module_from_ELF_DWARF_file

def newParseDWARF(debugFilepath):
    return create_module_from_ELF_DWARF_file(debugFilepath)

DW_GLO = 'DW_TAG_base_type'
DW_FUN = 'DW_TAG_subprogram'
DW_PAR = 'DW_TAG_formal_parameter'
DW_VAR = 'DW_TAG_variable'

DW_NAM = 'DW_AT_name'
DW_TYP = 'DW_AT_type'
DW_LOC = 'DW_AT_location'
DW_FB  = 'DW_AT_frame_base'

def parseDWARF(debugFilepath):
    """Returns a dict of dicts with functions mapped to stack variables"""
    with open(debugFilepath, mode='rb') as debugFile:
        elfFile = ELFFile(debugFile)
        if elfFile.has_dwarf_info():
            dwarfInfos = elfFile.get_dwarf_info()
            functions = {}
            for cu in dwarfInfos.iter_CUs():
                logging.info("Processing compilation unit DWARF info (version %d)" % cu.header['version'])
                for die in cu.iter_DIEs():
                    if die.tag == DW_FUN: # TODO: globals?
                        if DW_NAM in die.attributes:
                            currFun = str(die.attributes[DW_NAM].value, 'ascii')
                            logging.info("Processing function %s." % currFun)
                            functions[currFun] = {}
                            for child in die.iter_children():
                                if DW_NAM in child.attributes:
                                    stackElm = str(child.attributes[DW_NAM].value, 'ascii')
                                    functions[currFun][stackElm] = {'tag' : child.tag} # TODO: types?
                                    logging.debug("Found stack element %s." % stackElm)
                                else:
                                    logging.debug("Skipping %s" % str(child.tag))
                            logging.info("Found %d stack elements." % len(functions[currFun].keys()))
            return functions
        logging.warn("File %s does not contain any debug information." % debugFilepath)
    logging.warn("There was an error parsing file %s." % debugFilepath)
    return None

def _collectLocals(gdbOutput, funcDict):
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
                    
def _collectDisas(gdbOutput, funcDict):
    funcDict['disas'] = [tuple(line.strip().split('\\t')) for line in gdbOutput[1:-1]]

def staticGDB(debugFilepath, functions):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    logging.info("Loading file %s statically in GDB." % debugFilepath)
    gdbmi  = GdbController()
    result = gdbmi.write('file ' + debugFilepath)
    for func in functions.keys():
        result = gdbmi.write('info scope ' + func)
        result = [msg['payload'] for msg in result if msg['type']=='console']
        _collectLocals(result, functions[func])
        result = gdbmi.write('disas /r ' + func)
        result = [msg['payload'] for msg in result if msg['type'] == 'console']
        _collectDisas(result, functions[func])
    gdbmi.exit()
    return functions

def generateDebugLabel(functionName, functions):
    stackElements = []
    for stackElement in functions[functionName].keys():
        if 'offset' in functions[functionName][stackElement]:
            off  = functions[functionName][stackElement]['offset'][-1][1] # TODO: only looks at last offset
            size = functions[functionName][stackElement]['size']
            stackElements += [(stackElement, size, off)]
    return sorted(stackElements,key=lambda se : se[2])

def generateLabel(functionName, functions):
    return list(map(lambda x : x[1], generateDebugLabel(functionName, functions)))

def generateFeature(functionName, functions):
    ops = map(lambda x : x[1].replace(' ', ''), functions[functionName]['disas'])
    return 'START '+' '.join(ops)+' END'
