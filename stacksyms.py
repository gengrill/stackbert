# requires submodules pyelftools and dwarf_import
import os
import hashlib
import pdb
import logging
#import binaryninja

# TODO:
# BN's DWARF EH_FRAME processing most likely comes from this repo: https://github.com/francesco-zappa-nardelli/eh_frame_check/blob/master/testing/eh_frame_check.py
# there's some interesting test cases here https://git.tobast.fr/m2-internship/eh_frame_check_setup

from pygdbmi.gdbcontroller import GdbController
from elftools.elf.elffile import ELFFile

from dwarf_import.model.module import Module
from dwarf_import.model.elements import Function, Component, Parameter, LocalVariable, Location, Type, LocationType, ExprOp

from dwarf_import.io.dwarf_expr import ExprEval, LocExprParser
from dwarf_import.io.dwarf_import import DWARFDB, DWARFImporter
from dwarf_import.io.dwarf_import import place_component_in_module_tree

logging.basicConfig(
    format='{asctime} {levelname}:{funcName}:{message}',
    style="{", datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO
)

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
    '''Returns a list of functions for this file (if the file contains frame info section)'''
    logging.info(f"Trying to parse {filepath} as ELF")
    elf = ELFFile(open(filepath, 'rb'))
    module, importer = parseDWARF(elf)
    functions = getAllFunctions(module, importer, elf) # a list of model.elements.Function type objects
    frame_tables = collectFrameInfo(functions, elf) # global pc -> FDE dict
    functions = assign_frames(frame_tables, functions) # split per function
    functions = processRegisterRuleExpressions(functions, importer) # process dynamic register locs
    functions = propagateTypeInfo(functions, importer) # element.type.byte_size is None most of the time -> try and fix it
    functions = collectDisassemblyObjdump(functions, filepath)
    return functions

# TODO: if frame table is indeed missing, try generating it using https://github.com/frdwarf/dwarf-synthesis
def parseDWARF(elf):
    '''Look for .eh_frame section and if present, start parsing it (even stripped binaries retain frame info)'''
    if elf.has_dwarf_info(): # note that this does NOT mean 'has_debug_info()'
        logging.info("ELF file says it has some frame info..")
        module = Module() # this is high-level the data model (no deps on ELF/DWARF types etc)
        dwarfDB = DWARFDB(elf) # this the io data class for parsing
        importer = DWARFImporter(dwarfDB, dict()) # has state after parsing
        for component in importer.import_components():
            place_component_in_module_tree(module, component)
        return module, importer
    logging.warn("ELF file does not contain any stack frame information!")
    return None

def getAllFunctions(module, importer, elf):
    '''Returns all functions (including inlined functions).'''
    Function.arch  = property(lambda self : self._arch) # need this, e.g., for register descriptions
    Function.is_inline = property(lambda self : self._is_inline)
    functions = getFunctions(module)
    inlinedFs = getInlined(functions)
    logging.info(f"Found {len(inlinedFs)} inlined functions.")
    for func in functions:
        func._is_inline = False
        func._arch = elf.get_machine_arch()
    for func in inlinedFs:
        func._is_inline = True
        func._arch = elf.get_machine_arch()
    for func in inlinedFs: # by default, some inlined functions are missing.. we add them here
        parent = binary_search_function(func.start, functions)
        if parent is None:
            logging.warn(f"Inlined function without parent: {func}")
            continue
        if func not in parent.inlined_functions:
            if parent._inlined_functions == None:
                parent._inlined_functions = (func,)
            else:
                parent._inlined_functions += (func,)
    logging.info(f"Returning {len(functions)+len(inlinedFs)} functions total.")
    return inlinedFs + functions

def getFunctions(module):
    '''Recursively finds all functions (returns dwarf_import.model.elements.Function objects).'''
    functions = []
    for m in module.children():
        if type(m) == Module:
            functions += getFunctions(m)
        if type(m) == Component:
            logging.debug(f'Found {len(m.functions)} function definitions in component {m.name}')
            functions += m.functions
    logging.info(f"Found {len(functions)} function symbols.")
    return functions

# TODO: for some reason, there may be duplicates -> could be bug in dwarf_import?
def getInlined(functions):
    '''Recursively finds all inlined functions'''
    level = [inlined for func in functions for inlined in func.inlined_functions]
    if not any(level):
        return functions
    return level + getInlined(level)

def collectFrameInfo(functions, elf):
    '''Parses EH_FRAMES (or DEBUG_FRAMES respectively) to collect the frame tables (dict keyed by PC values as specified in DWARF Standard Section 6.4.1)'''
    from elftools.dwarf.callframe import ZERO
    dwarfInfo = elf.get_dwarf_info()
    if dwarfInfo.has_EH_CFI(): # ez
        logging.info('has .eh_frames')
        cfi_entries = dwarfInfo.EH_CFI_entries()
        frame_tables = dict() # pc -> frame description entry (FDE)
        for entry in cfi_entries: # The frame table is a list of dicts, where integer keys are register numbers for the architecture
            if not type(entry) == ZERO:
                frame_table = entry.get_decoded().table # elftools.dwarf.callframe.DecodedCallFrameTable
                if len(frame_table) == 0:
                    logging.warn(f'Empty frame table for entry {entry}!')
                    continue
                for entry in frame_table:
                    if 'pc' in entry:
                        if entry['pc'] not in frame_tables:
                            frame_tables[entry['pc']] = entry
                        else:
                            logging.warn(f"DOUBLE ENTRY: {entry}")
                    else:
                        logging.warn(f"ENTRY WITHOUT PC: {entry}")
        return frame_tables
    logging.warn('Does not contain .eh_frames section') # TODO: what about .debug_frames?
    return None

def binary_search_function(address, sorted_functions):
    '''Finds the function among the provided list that best matches the provided address (assuming linearly sorted func.start values and a contiguous code region)'''
    left = 0
    right = len(sorted_functions)-1
    while left <= right:
        mid = (left + right) // 2
        if sorted_functions[mid].start < address:
            left = mid + 1
        elif address < sorted_functions[mid].start:
            right = mid - 1
        else:
            return sorted_functions[mid]
    if sorted_functions[right].start <= address:
        return sorted_functions[right]
    elif sorted_functions[left].start <= address:
        return sorted_functions[left]
    return None

def assign_frames(frame_tables, functions):
    '''Assigns FDEs from frame_tables dict to functions by address matching fde['pc'] with func.start'''
    Function.frame_table = property(lambda self : self._frame_table) # dict of FDEs for this function as collected from EH_FRAME section (keyed by pc values)
    for func in functions:
        func._frame_table = None
    sorted_functions = sorted(functions, key=lambda func : func.start) # sort by start pc value once
    for pc, entry in frame_tables.items():
        func = binary_search_function(pc, sorted_functions)
        if func is None:
            logging.warn(f'No symbol for frame info {entry} at address {hex(pc)} (maybe it was inlined?)')
            continue
        logging.debug(f'Found frame info for function {func.name}@{hex(pc)}.')
        if func.frame_table is None:
            func._frame_table = dict()
        elif pc in func._frame_table:
            logging.warn(f"DOUBLE ENTRY: {entry} for {func.name}@{hex(pc)}!!!")
            func._frame_table[pc] = [func._frame_table[pc], entry]
        else:
            func._frame_table[pc] = entry
    return functions

def processRegisterRuleExpressions(functions, importer):
    '''Process per function frame tables to create Location objects for all registers stored on the stack'''
    # TODO this is a hack, should be part of the dwar_import processing.. maybe create a patch later
    # TODO right now, we are missing inlined functions that don't have their own frame table (some do)
    from collections import namedtuple
    from elftools.dwarf.descriptions import describe_reg_name
    Register = namedtuple('Register',['number','name','locations'])
    Register.type = Type(name='Register')
    Function.registers = property(lambda self : list(self._registers.values())) # property for retrieving the locations associated with registers stored on the stack
    
    # we get the register entries and create Location objects on the fly.
    for func in functions:
        Register.type._byte_size = getRegisterSize(func.arch)
        func._registers = dict() # TODO maybe flatten to be just a list of Register objects?
        if func.frame_table is not None:
            for pc in func.frame_table.keys(): # we aggregate locs across all pc values of the function body
                d = func.frame_table[pc]
                for regNo, regRule in d.items():
                    if type(regNo)==int: # only general purpose ('pc' and 'cfa' are not ints)
                        loc = None # TODO some locs here cause weird stack layout
                        if regRule.type == 'OFFSET' or regRule.type == 'VAL_OFFSET': # tuple here just unifies both cases to [1]
                            loc = Location(pc, 0x0, LocationType.STATIC_LOCAL, (0, regRule.arg))
                        elif regRule.type == 'EXPRESSION' or regRule.type == 'VAL_EXPRESSION':
                            loc = importer._location_factory.make_location(pc, 0x0, regRule.arg)
                        else: # TODO There was a bug here with location start set to func.start isntead of pc.. there may be several more; not clear how to produce location objects correctly from register rules
                            logging.warn(f"Unknown Register Rule: {regRule}")
                            loc = Location(pc, 0x0, LocationType.STATIC_LOCAL, (0, regRule.arg))
                        if regNo not in func._registers:
                            func._registers[regNo] = Register(regNo, describe_reg_name(regNo, func.arch), set())
                        func._registers[regNo].locations.update({loc}) # possibly multiple locs per register (e.g., depending on control flow)
    return functions

def getRegisterSize(arch):
    return {
        'x86'     : 4,
        'x64'     : 8,
        'ARM'     : 4,
        'AArch64' : 8,
        'MIPS'    : 8,
    }[arch]

# TODO There seem to be two remaining 'None' type sources: VOID and VARIADIC.
#      Not sure if there is a general way of dealing with them correctly,
#      so we don't provide any size information for them at the moment.
def propagateTypeInfo(functions, importer):
    types = set() #for Type in importer._type_factory.iter_types():
    for function in functions:
        for parameter in function.parameters:
            if parameter.type is None:
                logging.warn(f"Parameter {parameter} has 'None' Type association!")
                continue
            types |= {parameter.type}
        for variable in function.variables:
            if variable.type is None:
                logging.warn(f"Variable {variable} has 'None' Type association!")
                continue
            types |= {variable.type}
    logging.debug(f"Type list for functions: {types}")
    for _type in types:
        if not _type.is_qualified_type and _type.byte_size is None:
            if _type.array_count is not None:
                arrayType = resolveType(_type)
                if not arrayType.is_base:
                    logging.warn(f"Can't resolve array type {_type}!")
                    continue
                _type._byte_size = _type.array_count * arrayType.byte_size # TODO check correctness
            elif _type.composite_type is not None:
                logging.warn(f"Can't yet handle composite type {_type}!")
            elif _type.element is not None: # this is the frequent case
                base = resolveType(_type)
                if base.byte_size is None:
                    logging.warn(f"Type propagation for type {base} yields size 'None'!")
                    continue
                _type._byte_size = base._byte_size # TODO check correctness
    return functions

def resolveType(_type):
    return _type if _type.element is None else resolveType(_type.element)

# TODO: we should probably incorporate 'sub $0x48,%rsp' type instructions here
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
    inlined = [getStackElements(inlined) for inlined in function.inlined_functions]
    logging.info(f"Got {len(inlined)} inlined functions for {function.name}")
    possibleStackElements = [function.parameters, function.variables, function.registers]
    return max(map(getMinOff, possibleStackElements + inlined))
    #return abs(min(map(getMinOff, possibleStackElements + inlined)))

# TODO: for LLVM this gets better results than min (check with "git diff --no-index --word-diff=color --word-diff-regex=. new old")
def getMinOff(stkElms): # minimal stack offset across all elements
    return max(map(abs,[0]+[loc.expr[1] for stkElm in stkElms for loc in getStackLocations(stkElm)]))
    #return min([0]+[loc.expr[1] for stkElm in stkElms for loc in getStackLocations(stkElm)])

def generateDebugLabel(func):
    funElms  = len(func.parameters) + len(func.variables) + len(func.registers)
    stkSlots = sorted(getStackElements(func), key=getMinStackOff)
    if len(stkSlots) != funElms:
        logging.info(f"Function {func.name} has {len(stkSlots)} stack elements out of {funElms} total.")
    logging.debug(f"{func.name} => [{', '.join(stkElm.name+'@ebp%+d'%getMinStackOff(stkElm) for stkElm in stkSlots)}]")
    return [stkElm.type.byte_size for stkElm in stkSlots]

def getStackElements(function):
    '''return stack elements (in no particular order)'''
    candidates = function.parameters + function.variables + function.registers
    logging.debug(f"Function {function.name}@{function.start} has {len(candidates)} potential stack elements.")
    return [stkElm for stkElm in candidates if any(getStackLocations(stkElm))]

def getMinStackOff(stkElm): # minimal stack offset for a single element
    stkLocs = getStackLocations(stkElm)
    logging.debug(f"Stack element {stkElm} has {len(stkLocs)} stack locations (there might be more non-stack locations for this object).")
    return min(map(lambda stkLoc : stkLoc.expr[1], stkLocs))

def getStackLocations(stkElm):
    if None in stkElm.locations:
        print("BUG!!! NO LOCATIONS FOR: ", stkElm) # TODO I think this should be fixed now
    return [loc for loc in stkElm.locations if locExprHasOffset(loc)]

def locExprHasOffset(location): # TODO y0 d4wg, this sh!t is sketchy as f*&^
    if not hasattr(location, 'expr'): # TODO: should be fixed now???
        print(type(location), location)
    if len(location.expr) > 1 and type(location.expr[1]) == int:
        return True
    return False

def checkLabels(functions):
    logging.info(f"Start collecting labels for {len(functions)} functions..")
    allLabels = {}
    for func in functions:
        frame = getMaxFrameSize(func)
        label = generateDebugLabel(func)
        if any(True for slotSize in label if slotSize is None):
            logging.warn(f"Function {func.name} has VOID or VARIADIC type stack objects; cannot determine frame size reliably!")
            continue
        if 8 < abs(sum(label)-frame): # off by more than 8 bytes
            logging.warn(f"Label generation for {func.name} is not sound (got {frame} by offset, but {sum(label)} by size)!")
            continue # TODO: previously, we included these in the training
        logging.info(f"{func.name} ({frame} by offset / {sum(label)} by size) => {label}")
        allLabels[func.name] = {}
        allLabels[func.name]['inp'] = func.disas #' '.join(map(lambda t : t[1], func.disas))
        allLabels[func.name]['max'] = frame
        allLabels[func.name]['out'] = label
    return allLabels

def collectDisassemblyObjdump(functions, filepath):
    logging.info('Trying to collect function disassembly via objdump..')
    import subprocess
    filedisas = subprocess.getoutput(f"objdump -r -j .text -d {filepath}")
    for func in functions: # we use awk for cut2 since cut doesn't like Python's TAB insertion
        function = f"awk -v RS= '/^[[:xdigit:]]+ <{func.name}>/'"
        cut1, cut2 = "cut -d: -f2", "awk -F'\t' '{print $2}'"
        proc = subprocess.Popen(' | '.join([function, cut1, cut2]), shell=True, \
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=bytes(filedisas, encoding='utf-8'))
        if len(err) != 0:
            logging.warn(f"Error during disassembly of {func.name}: " + err.decode('utf-8'))
        lines = out.decode('utf-8').strip().split('\n')
        func.disas = ' '.join(map(lambda s : s.replace(' ', ''), lines))
    return functions

def validateWithGDB(functions, filepath, _gdbmi):
    '''Collects the same info we parsed from .eh_frames section manually using GDB's output for validation.'''
    logging.info("Attempting to validate frame size and stack symbolization info using GDB..")
    if _gdbmi is None:
        _gdbmi = GdbController() 
    functions = collectLocals(_gdbmi, functions, filepath)
    functions = collectDisassembly(_gdbmi, functions, filepath)
    if _gdbmi is None:
        _gdbmi.exit()
    return functions

# def collectDisasLabels(functions):
#     allLabels = {}
#     for func in functions:
#         disas = ' '.join(map(lambda t : t[1], func.disas))[:1535]
#         md5 = hashlib.md5(disas.encode()).hexdigest()
#         allLabels[md5] = {}
#         allLabels[md5]['disas'] = disas
#         allLabels[md5]['indices'] = []
#         index = 0
#         for tup in func.disas:
#             sz = len(tup[1].split(' '))
#             allLabels[md5]['indices'].append((index, sz))
#             index += sz
#     return allLabels

# TODO use GDB for validation only -> collect disas somewhere else (where?)
def collectDisassemblyGDB(gdbmi, functions, debugFilepath):
    logging.info('Trying to collect function disassembly via GDB..')
    disasQueries = [f'disas /r {func.name}' for func in functions]
    gdbOut = staticGDB(gdbmi, debugFilepath, functions, disasQueries)
    for disas, func in zip(gdbOut, functions):
        func.disas = [tuple(line.strip().split('\\t')) for line in disas[1:-1]]
    return functions

# def generateDisasFeature(functions):
#     lines = []
#     for func in functions:
#         if 0<len(func.disas):
#             lines += [func.name+'@'+hex(func.start)+':',  ' '.join(map(lambda t : t[1], func.disas))]
#         else:
#             logging.warn(f"Found no disassembly for {func.name}@{func.start} while generating input features!")
#     return lines

# collects function locals via GDBs 'info scope function' command
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

def staticGDB(gdbmi, filepath, functions, queries):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    logging.info(f"Loading {filepath} statically in GDB.")
    result = [gdbmi.write(f"-file-exec-and-symbols {filepath}")]
    for q in queries:
        result += [[msg["payload"] for msg in gdbmi.write(q) if msg["type"]=="console"]]
    return result[1:] # skip meta output

# TODO Unused. At the moment we're not using control flow to improve our heuristic stack frame measure..
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

# TODO Unused. At the moment we're not using control flow to improve our heuristic stack frame measure..
def isInReg(variable): # TODO should be named "isInRegInInitialFrame"
    initFrameLoc = variable.locations[0]
    if len(initFrameLoc) == 1:
        return True # TODO: implement the check
    return False
