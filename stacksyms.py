import os
import logging
logging.basicConfig(format='%(asctime)s %(levelname)s:%(funcName)s:%(message)s',   \
                    datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)

# requires pyelftools and pygdbmi, install with "pip3 install pyelftools pygdbmi"
from pygdbmi.gdbcontroller import GdbController
from elftools.elf.elffile import ELFFile

# from https://github.com/Vector35/dwarf_import
from dwarf_import.model.module import Module
from dwarf_import.model.elements import Component, Parameter, LocalVariable, Location, Type, LocationType, ExprOp
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

def parseELF(filepath, validateWithGDB=False, gdbmi=None):
    '''Returns a list of functions for this file (if the file contains debug info)'''
    logging.info(f"Trying to parse {filepath} as ELF")
    elf = ELFFile(open(filepath, 'rb'))
    module, importer = parseDWARF(elf)
    functions = getFunctions(module) # a list of model.elements.Function type objects
    logging.info(f"Found {len(functions)} functions.")
    functions = collectFrameInfo(functions, elf)
    functions = processExpressions(functions, importer) # process dynamic register locs
    if validateWithGDB:
        # collect the same info we parsed from .eh_frames section for validation
        _gdbmi  = gdbmi if gdbmi is not None else GdbController() 
        functions = collectLocals(_gdbmi, functions, filepath)
        functions = collectDisassembly(_gdbmi, functions, filepath)
        if gdbmi is None:
            _gdbmi.exit()
    return functions

def processExpressions(functions, importer):
    # TODO this is a hack, should be part of the dwar_import processing.. maybe create a patch later
    from collections import namedtuple
    from elftools.dwarf.descriptions import describe_reg_name
    Register = namedtuple('Register',['number','name','locations'])
    # The frame table is a list of dicts, where integer keys are register numbers for the architecture.
    # So we get the register entries and create Location objects on the fly..
    for func in functions:
        func.registers = dict() # TODO maybe flatten to be just a list of Register objects?
        for d in func.frame:
            for regNo, regRule in d.items():
                if type(regNo)==int:
                    loc = None
                    if regRule.type == 'OFFSET': # the tuple here just unifies both cases to [1]
                        loc = Location(func.start, 0x0, LocationType.STATIC_LOCAL, (0, regRule.arg))
                    elif regRule.type == 'EXPRESSION':
                        loc = importer._location_factory.make_location(func.start, 0x0, regRule.arg)
                    if regNo not in func.registers:
                        func.registers[regNo] = Register(regNo, describe_reg_name(regNo, func.arch), set())
                    func.registers[regNo].locations.update({loc})
    return functions

def parseDWARF(elf):
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

def getFunctions(module):
    '''Returns a list of dwarf_import.model.elements.Function objects.'''
    functions = []
    for m in module.children():
        if type(m) == Module:
            functions += getFunctions(m)
        if type(m) == Component:
            logging.debug(f'Found {len(m.functions)} function definitions in component {m.name}')
            functions += m.functions
    return functions

def getMaxFrameSize(function):
    '''Get maximum frame size based on its parameter, local, and stored register offsets.
       The number we compute here statically from the .eh_frame section can actually be validated using GDB:
       ./gdb path/to/prog
       (gdb) set confirmation off
       (gdb) break {func.name}
       (gdb) r
       (gdb) rbreak .
       (gdb) c
       (gdb) info frame
       At this point "frame at 0xADDRESS_A" - "called by frame at 0xADDRESS_B" should match our number below'''
    return abs(min(getMinOff(function.parameters), getMinOff(function.variables), getMinOff(function.registers.values())))

def locExprHasOffset(location): # TODO y0 d4wg, this sh!t is sketchy as f*&^
    if len(location.expr) > 1 and type(location.expr[1]) == int:
        return True
    return False

def getMinOff(stkElms):
    return min([0]+[loc.expr[1] for stkElm in stkElms for loc in filter(locExprHasOffset, stkElm.locations)])

def collectFrameInfo(functions, elf):
    from elftools.dwarf.callframe import ZERO
    dwarfInfo = elf.get_dwarf_info()
    if dwarfInfo.has_EH_CFI():
        logging.info('has .eh_frames')
        cfi_entries = dwarfInfo.EH_CFI_entries()
        for entry in cfi_entries:
            if not type(entry) == ZERO:
                frame_table = entry.get_decoded().table # elftools.dwarf.callframe.DecodedCallFrameTable
                if len(frame_table) == 0:
                    logging.warn(f'Empty frame table for entry {entry}!')
                    continue
                for func in functions: # TODO these two loops take forever.. rewrite as lookup
                    if any(filter(lambda d : func.start == d['pc'], frame_table)):
                        logging.info(f'Found frame info for function {func.name}.')
                        func.frame = frame_table
                        func.arch  = elf.get_machine_arch() # need this, e.g., for register descriptions
        return functions
    logging.warn('Does not contain .eh_frames section')
    return functions

def collectDisassembly(gdbmi, functions, debugFilepath):
    logging.info('Trying to collect function bodies via GDB..')
    disasQueries = [f'disas /r {func.name}' for func in functions]
    gdbOut = staticGDB(gdbmi, debugFilepath, functions, disasQueries)
    for disas, func in zip(gdbOut, functions):
        func.disas = [tuple(line.strip().split('\\t')) for line in disas[1:-1]]
    return functions

def collectLocals(gdbmi, functions, debugFilepath):
    logging.info("Trying to collect stack locals via GDB..")
    scopeQueries = [f"info scope {func.name}" for func in functions]
    gdbOut = staticGDB(gdbmi, debugFilepath, functions, scopeQueries)
    for scope, func in zip(gdbOut, functions):
        symbol, size, off = None, None, None
        for line in scope: # depends on line order of GDB output
            if line.find('Symbol') != -1: # Symbol name comes first
                symbolName = line.split(' ')[1]
                logging.debug(f"Found stack element {symbolName}.")
                size, off = None, None
                symbol = next((p for p in func.parameters if symbolName==p.name), None)
                if symbol is None:
                    logging.debug("Not a parameter, maybe local?")
                    symbol = next((l for l in func.variables if symbolName==l.name), None)
                    if symbol is None:
                        logging.warning(f"Stack symbol {symbolName} reported by GDB but not by PyELFTools.")
                        continue
                logging.debug(f"Found scope info for stack element {symbol}")
            elif symbol is not None and line.find("length") != -1: # Size usually comes last
                size = int(line[line.find('length') + 6 : -3])
                logging.debug(f"GDB reports size info ({size} bytes)!")
                logging.info("Locations: " + str(list(map(lambda loc : f"begin={hex(loc.begin)}, end={hex(loc.end)}", symbol.locations))))
                if symbol.type.byte_size is None:
                    logging.warning(f"Setting previously unknown size to {size} bytes!")
                    symbol.type._byte_size = size
                elif symbol.type.byte_size != size:
                    logging.warning(f"GDB size ({size}) and PyELFTtools size ({symbol.type.byte_size}) differ!")
                else:
                    logging.debug("GDB size and PyELFTools size are equal.")
            elif symbol is not None and line.find("DW_OP_fbreg") != -1: # Location second (maybe multiple, but focus on frame offsets)
                if not any(symbol.locations):
                    off = line.split(' ')[6::]
                    begin = int(off[1][0:-2])
                    loc = Location(begin, 0, LocationType.STATIC_LOCAL, off)
                    logging.info(f"Adding location {loc}.")
                    symbol.add_location(loc)
                logging.debug("Has stack location!")
    return functions

# using GDB for two reasons: (1) it gives us both disassembly and local variables, and (2) everyone has it
def staticGDB(gdbmi, filepath, functions, queries):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    logging.info(f"Loading {filepath} statically in GDB.")
    result = [gdbmi.write(f"-file-exec-and-symbols {filepath}")]
    for q in queries:
        result += [[msg["payload"] for msg in gdbmi.write(q) if msg["type"]=="console"]]
    return result[1:] # skip meta output


# remaining stuff is WIP and not currently usable

def generateDebugLabel(func):
#    TODO
    stackVars = filter(func.variables, isOnStack)
#    return [
#                print(hex(loc.begin) + " to " + hex(loc.end) + ": " \
#                      + str(loc.type)[13:] + str(loc.expr))

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
