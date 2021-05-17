# stacksyms.py: requires submodules pyelftools and dwarf_import
# The purpose of this tool is to extract function features and labels
# from unstripped, compiler-generated ELF files. While it doesn't
# stricly require debug information (only .eh_frame and .symtab) it
# certainly helps in generating better ground truth information.
import os
import logging
import elftools
import dwarf_import

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import ExprDumper, describe_reg_name, describe_CFI_register_rule, describe_CFI_CFA_rule

from dwarf_import.model.module import Module
from dwarf_import.model.elements import Component, Parameter, LocalVariable, Location, Type, LocationType, ExprOp

from dwarf_import.io.dwarf_expr import ExprEval, LocExprParser
from dwarf_import.io.dwarf_import import DWARFDB, DWARFImporter
from dwarf_import.io.dwarf_import import place_component_in_module_tree

from typing import Optional

class Register(dwarf_import.model.elements.Element):
    type = Type(name='Register')
    def __init__(self, number, name, locations):
        super().__init__(owner=None, name=name)
        self.locations = locations # iterable (e.g., set)
        self.number = number # int or str
    def __repr__(self):
        return f'<Register: number={self.number}, name={self.name}, locations={self.locations}>'

class Function(dwarf_import.model.elements.Function):
    @classmethod
    def fromDWARFFunction(cls, old: dwarf_import.model.elements.Function):
        new = cls(owner=old.owner, name=old.name, start=old.start)
        new._return_type = old._return_type
        new._access = old._access
        new._no_return = old._no_return
        for p in old._parameters:
            new.add_parameter(p.clone())
        for v in old._variables:
            new.add_variable(v.clone())
        if hasattr(old, '_attributes'):
            new._attributes = dict(old._attributes)
        return new
    
    def __init__(self, owner = None, name: str = 'function', start: Optional[int] = None):
        super().__init__(owner, name, start)
        self._is_inline = False
        self._arch = '' # arch string (e.g., 'arm', 'AArch64', 'x86', 'x64')
        self._size = 0  # size of function code in bytes
        self._frame_table = None # FDE or None
        self._registers = dict()
        self._code = None # opcode string as bytes object

    @property
    def is_inline(self) -> bool:
        return self._is_inline

    @property
    def arch(self) -> str:
        return self._arch

    @property
    def size(self) -> int:
        return self._size

    @property
    def frame_table(self) -> elftools.dwarf.callframe.FDE:
        return self._frame_table

    @property
    def registers(self) -> list:
        return list(self._registers.values())

    @property
    def code(self) -> str:
        if self._code is not None:
            return self._code.hex()
        return ''

logging.basicConfig(
#    filename='stacksyms_run.log',
    format='{asctime} {levelname}:{funcName}:{message}',
    style="{", datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO,
)

# Vector35's dwarf_import library has:
#   (1) the io classes which deal with ELF/DWARF stuff,
#   (2) the model classes which are more general, high-level data containers
#   (3) the parsers themselves which are stateful because DWARF contains stack machines
# We may need all of the above to get what we want, because some things (like lineprograms)
# are not implemented in dwarf_import (or any other library I looked at).
#
# Vector 35's DWARF EH_FRAME processing most likely comes from this repo:
# https://github.com/francesco-zappa-nardelli/eh_frame_check/blob/master/testing/eh_frame_check.py
# there are some interesting test cases here https://git.tobast.fr/m2-internship/eh_frame_check_setup

def parseDirectory(dirPath):
    fmap = {fname : parseELF(dirPath + os.sep + fname) for fname in next(os.walk(dirPath))[2]}
    logging.info(f"Found {sum(map(len,functions))} functions total in {len(functions)} files.")
    return fmap

def parseELF(filepath):
    '''Returns a list of functions for this file (if the file contains frame info section)'''
    logging.info(f"Trying to parse {filepath} as ELF")
    elf = ELFFile(open(filepath, 'rb'))
    logging.info(f"ELF file is for architecture {elf.get_machine_arch()}.")
    module, importer = parseDWARF(elf)
    func_dict = getAllFunctions(module, importer, elf) # a map of int (pc values) -> model.elements.Function
    frame_tables = collectFrameInfo(func_dict, elf) # int (pc values) -> FDE dict
    func_dict = assign_frames(frame_tables, func_dict) # split per function
    func_dict = processRegisterRuleExpressions(func_dict, importer) # process dynamic register locs
    func_dict = propagateTypeInfo(func_dict, importer) # element.type.byte_size is often None -> try and fix it
    func_dict = collectOpcodes(func_dict, elf)
    processInlineFunctions(func_dict, importer, elf)
    return func_dict.values()

# TODO: if frame table is indeed missing, try generating it using https://github.com/frdwarf/dwarf-synthesis
def parseDWARF(elf):
    '''Look for .eh_frame section and if present, start parsing it (even stripped binaries retain frame info)'''
    if elf.has_dwarf_info(): # note that this does NOT mean 'has_debug_info()'
        logging.info("ELF file says it has some frame info..")
        module = Module() # this is high-level the data model (no deps on ELF/DWARF types etc)
        dwarfDB = DWARFDB(elf) # this the io data class for parsing
        importer = DWARFImporter(dwarfDB, dict()) # {'only_concrete_subprograms' : False})
        for component in importer.import_components():
            place_component_in_module_tree(module, component)
        return module, importer # importer has state after parsing
    logging.warn("ELF file does not contain any stack frame information!")
    return None

# I noticed this used to do a bad job at finding functions for some files, e.g., it
# only detected 2 functions for "data/cross-compile-dataset/bin/static/gcc/o1/pee".
# This seems to be a limitation of dwarf_import, because it relies on the information
# provided in the '.debug_info' section to find functions. That may however not be very
# reliable.. I added two alternatives that I think should do a better job below.
# If we also change the "is_concrete" requirement as a default import setting for DWARFImporter
# it will import 13 functions (as opposed to 2) but curiously miss start address and size info.
def getAllFunctions(module, importer, elf):
    '''Returns all function definitions as dwarf_import.model.elements.Function objects.'''
    # (1) from the .symtab section (name, address, and size only)
    func_dict = getFunctionsFromSymtab(elf)
    # TODO: (2) from the .eh_frame section (no names but frame size and address ranges)
    # (3) from .debug_info using 'DW_TAG_subprogram' (can miss .start if only_concrete_subprograms=False)
    func_dict = getFunctionsFromDWARFInfo(func_dict, module)
    return func_dict

# need to process inline functions to obtain full frame information for parent functions
def processInlineFunctions(func_dict, importer, elf):
    inlinedFs = {func.start : func for func in getInlined(func_dict.values()) if func.start not in func_dict}
    if len(inlinedFs) == 0:
        return
    logging.debug(f"Found {len(inlinedFs)} inlined functions.")
    sorted_funcs = sorted(func_dict.values(), key=lambda f : f.start)
    for func in inlinedFs.values(): # by default, some inlined functions are missing.. we add them here
        func._is_inline = True
        func._arch = elf.get_machine_arch()
        parent = binary_search_function(func.start, sorted_funcs)
        if parent is None:
            logging.warn(f"Inlined function without parent: {func}")
            continue
        if func not in parent.inlined_functions:
            if parent._inlined_functions == None:
                parent._inlined_functions = (func,)
            else:
                parent._inlined_functions += (func,)
    inlined_frame_tables = collectFrameInfo(inlinedFs, elf)
    inlinedFs = assign_frames(inlined_frame_tables, inlinedFs)
    inlinedFs = processRegisterRuleExpressions(inlinedFs, importer)
    inlinedFs = propagateTypeInfo(inlinedFs, importer)

# TODO: for some reason, there may be duplicates?
def getInlined(functions):
    '''Recursively finds all inlined functions'''
    level = [inlined for func in functions for inlined in func.inlined_functions]
    if not any(level):
        return functions
    return level + getInlined(level)

def getFunctionsFromSymtab(elf):
    '''Get both local and global symbols from .symtab section.'''
    logging.info('Trying to obtain symbol information.')
    Register.type._byte_size = getRegisterSize(elf.get_machine_arch()) # TODO per instance would be better
    func_dict = dict()
    symtab = elf.get_section_by_name('.symtab')
    if symtab is None:
        logging.critical("Missing .symtab section!")
        return func_dict
    for i, symbol in enumerate(symtab.iter_symbols()):
        if symbol['st_info']['type']=='STT_FUNC':
            if symbol['st_value'] not in func_dict:
                new_func = Function(name=symbol.name, start=symbol['st_value'])
                new_func._arch = elf.get_machine_arch()
                new_func._size = symbol['st_size']
                func_dict[symbol['st_value']] = new_func
    logging.info(f'Found {len(func_dict)} functions according to symbol table')
    return func_dict

def getFunctionsFromDWARFInfo(func_dict, module):
    '''Recursively finds functions using 'DW_TAG_subprogram'.'''
    logging.info(f'Searching for subroutines with explicit DWARF info..')
    for m in module.children():
        if isinstance(m, Module):
            logging.debug(f'Recursing into module {m}')
            getFunctionsFromDWARFInfo(func_dict, m)
        elif isinstance(m, Component):
            logging.debug(f'Found {len(m.functions)} function definitions in component {m.name}')
            func_dict = mergeSymtabDWARF(func_dict, m.functions)
        else:
            logging.critical(f'Child node is neither Module nor Component ({type(m), m}).')
    return func_dict

def mergeSymtabDWARF(symtab_funcs, dwarf_funcs):
    for dwarf_func in dwarf_funcs:
        if dwarf_func.start is None: # try to match it by name
            for symtab_func in symtab_funcs.values():
                if symtab_func.name == dwarf_func.name:
                    logging.info(f'Found missing address from symtab info for {dwarf_func.name}.')
                    dwarf_func.start = symtab_func.start
                    break
            else: # this case only hits if we did not break the inner loop
                logging.info(f'Skipping abstract function {dwarf_func.name} (missing address).')
                continue # we then skip processing in the outer loop (because there's no matching function)
        if dwarf_func.start in symtab_funcs: # merge symtab and DWARF symbols by address
            logging.debug(f'Merging symtab and dwarf info for {dwarf_func.name}@{hex(dwarf_func.start)}.')
            symtab_func = symtab_funcs[dwarf_func.start]
            new_func = Function.fromDWARFFunction(dwarf_func)
            new_func._size  = symtab_func.size
            new_func._arch  = symtab_func.arch
            symtab_funcs[new_func.start] = new_func
            del symtab_func
    return symtab_funcs

def collectFrameInfo(func_dict, elf):
    '''Parses .eh_frames to collect frame tables per function (specified in DWARF Standard Section 6.4.1)'''
    from elftools.dwarf.callframe import CIE, FDE, ZERO
    dwarfInfo = elf.get_dwarf_info()
    if dwarfInfo.has_EH_CFI(): # ez
        logging.info('has .eh_frames')
        cfi_entries = dwarfInfo.EH_CFI_entries()
        frame_tables = dict() # func.start -> frame description entry (FDE)
        for entry in cfi_entries: # FDEs or CIEs
            if isinstance(entry, FDE): # CIEs don't specify initial locations, only FDEs do
                fpc = entry['initial_location']
                func = func_dict[fpc] if fpc in func_dict else None
                if func is None:
                    logging.warn(f"FDE/CIE for address {hex(entry['initial_location'])} without matching symbol.")
                    continue
                frame_tables[func.start] = entry
        return frame_tables
    logging.critical('File does not contain .eh_frames section') # TODO: handle .debug_frames
    return func_dict

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

def assign_frames(frame_tables, func_dict):
    '''Assigns FDEs from frame_tables dict to functions by address matching fde['pc'] with func.start'''
    for func in func_dict.values():
        func._frame_table = None
        if func.start not in frame_tables:
            if not func.is_inline:
                logging.critical(f"No frame table for {func.name}@{hex(func.start)}!")
            continue
        entry = frame_tables[func.start] # FDE for function as defined in .eh_frames section
        decoded_table = entry.get_decoded() # elftools.dwarf.callframe.DecodedCallFrameTable
        if len(decoded_table) == 0:
            logging.warn(f'Frame table for function {func.name} is empty!')
            continue
        func._frame_table = entry
    return func_dict

def processRegisterRuleExpressions(func_dict, importer):
    '''Process per function frame tables to create Location objects for all registers stored on the stack'''
    # TODO this is a hack, should be part of the dwar_import processing.. maybe create a patch later
    # TODO right now, we are missing inlined functions that don't have their own frame table (some do)
    for func in func_dict.values():
        if func.frame_table is not None:
            decoded_table = func.frame_table.get_decoded()
            ra_regnum = func.frame_table.cie['return_address_register']
            reg_order = sorted(filter(lambda r : r != ra_regnum, decoded_table.reg_order))
            for line in func.frame_table.get_decoded().table: # process the entire function body
                if 'cfa' in line: # canonical frame address rule for this line
                    processCFARule(line, func, importer)
                for regNo in reg_order: # general purpose register rules for this line
                    if regNo in line:
                        processRegisterRule(regNo, line, func, importer)
    return func_dict

def processCFARule(line, func, importer):
    pc = line['pc'] # start address for rules in this line
    cfa_loc = None
    if line['cfa'].expr:
        cfa_loc = importer._location_factory.make_location(pc, 0, line['cfa'].expr)
    else:  # tuple (0, ) unifies access to [1] in all cases later
        cfa_loc = Location(pc, 0, LocationType.STATIC_LOCAL, (0, line['cfa'].offset))
    if 'cfa' not in func._registers:
        func._registers['cfa'] = Register('cfa', describe_reg_name(line['cfa'].reg, func.arch), set())
    if cfa_loc is not None:
        func._registers['cfa'].locations.update({cfa_loc})
    else:
        logging.critical(f"Can't parse location for CFA rule {describe_CFI_CFA_rule(line['cfa'])} in {func.name}.")

def processRegisterRule(regNo, line, func, importer):
    pc = line['pc'] # start address for rules in this line
    loc = None # FIXME some locs here cause weird stack layout (e.g., [8,8,4,1,4,8] -> why 1)???
    if line[regNo].type in ['OFFSET', 'VAL_OFFSET']: # LocFactory raises a TypeError in this case
        loc = Location(pc, 0, LocationType.STATIC_LOCAL, (0, line[regNo].arg))
    elif line[regNo].type in ['EXPRESSION', 'VAL_EXPRESSION']:
        loc = importer._location_factory.make_location(pc, 0, line[regNo].arg)
        if loc is None:
            logging.critical(f"Can't parse loc expr {describe_CFI_register_rule(line[regNo])} ({func.name}).")
            return
    else: # in this case we don't have a stack location but, e.g., another register
        logging.debug(f"No stack locs for {describe_CFI_register_rule(line[regNo])} in {func.name}.")
        return
    if regNo not in func._registers:
        func._registers[regNo] = Register(regNo, describe_reg_name(regNo, func.arch), set())
    func._registers[regNo].locations.update({loc})

def getRegisterSize(arch):
    return {
        'x86'     : 4,
        'x64'     : 8,
        'ARM'     : 4,
        'AArch64' : 8,
    }[arch]

# TODO There seem to be two remaining 'None' type sources: VOID and VARIADIC.
#      Not sure if there is a general way of dealing with them correctly,
#      so we don't provide any size information for them at the moment.
def propagateTypeInfo(func_dict, importer):
    types = set() #for Type in importer._type_factory.iter_types():
    for function in func_dict.values():
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
        if not _type.is_qualified_type or _type.byte_size is None:
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
    return func_dict

def resolveType(_type):
    return _type if _type.element is None else resolveType(_type.element)

# There are different ways we could try to get a number for the stack frame size of a binary
# function statically, but none of them seems satisfactory for various reasons.
# Specficially, we can obtain per-function frame sizes statically by:
# (1) emitting stack size during compilation ("-fstack-usage")
# (2) counting pushs and pops, also considering "sub 0x48, rsp" type instructions
# (3) looking at the maximal offset of the cfa column in the function's .eh_frame table
# (4) collecting all stack elements from 'DW_TAG_variable' and 'DW_TAG_formal_parameter',
#     calculating their respective sizes, and summing up the total size.
# The first option is obviously going to be compiler and architecture-specific, limited to programs
# where source code and target compiler are both available. These constraints are quite limiting.
# The second option works reasonably well in practice, but requires accurate disassembly and modeling
# of stack operations for each architecture (TODO: are there other downsides???).
# The third option may provide an actual number most of the time, but some compilers seem to generate
# code that keeps the base pointer in a register
def getMaxFrameSize(function):
    '''Get maximum frame size of a function based on its .eh_frame entry.
       The number we obtain here statically can actually be validated at runtime (e.g, using GDB):
       $ gdb path/to/prog
       (gdb) set confirmation off
       (gdb) break {func.name}
       (gdb) r
       (gdb) rbreak .
       (gdb) c
       (gdb) info frame
       At this point "frame at 0xADDRESS_A" - "called by frame at 0xADDRESS_B" should match our number below'''
    # TODO: the approach in comments here would require successful symbolization.. but we're not there yet
    inlined = [getStackElements(inlined) for inlined in function.inlined_functions]
    logging.debug(f"Got {len(inlined)} inlined functions for {function.name}")
    possibleStackElements = [function.parameters, function.variables, function.registers]
    return max(map(abs,map(getMaxOff, possibleStackElements + inlined)))

def getMaxFrameSizeCFA(function):
    if 'cfa' in function._registers:
        # return max(line['cfa'].offset for line in function.frame_table.table)
        return max([0] + [loc.expr[1] for loc in getStackLocations(function._registers['cfa'])])
        '''
        cfa_locs_with_exprs = list(filter(lambda reg : reg.location.expr is not None, cfa_rules))
        if any(cfa_locs_with_exprs): # seems to be rare, but we might be skipping over offsets here.. logging
            logging.info("Binary contains register rule expression for canonical frame address, skipping:")
            ra_regnum = function.frame_table.cie['return_address_register']
            logging.info(f"return address in register {ra_regnum} ({describe_reg_name(ra_regnum, function.arch)}")
            expr_dumper = ExprDumper(function.frame_table.structs)
            for loc in cfa_locs_with_exprs:
                logging.info(f"Skipping Expression: {expr_dumper.dump_expr(loc.expr)}")
                cfa_rules.remove(cfar)
        return max(loc.offset for cfa in cfa_rules)
        '''
    logging.critical(f"No canonical frame address for {function.name}.. returning zero!")
    return 0

# for LLVM max of abs gets better results than min ("git diff --no-index --word-diff=color --word-diff-regex=. new old")
def getMaxOff(stkElms): # maximal stack offset across all elements
   return max(map(abs,[0]+[loc.expr[1] for stkElm in stkElms for loc in getStackLocations(stkElm)]))

def generateDebugLabel(func):
    funElms  = len(func.parameters) + len(func.variables) + len(func.registers)
    stkSlots = sorted(getStackElements(func), key=getMaxStackOff)
    if len(stkSlots) != funElms:
        logging.info(f"Function {func.name} has {len(stkSlots)} stack elements out of {funElms} total.")
    logging.debug(f"{func.name} => [{', '.join(stkElm.name+'@ebp%+d'%getMaxStackOff(stkElm) for stkElm in stkSlots)}]")
    return [stkElm.type.byte_size for stkElm in stkSlots] #  if stkElm.type not in [Type._VOID, Type._VARIADIC]]

# FIXME for some reason Location.pc may be 0 for some local variables, even if line['pc'] is nonzero
def getStackElements(function):
    '''return stack elements (in no particular order)'''
    regs = [reg for reg in function.registers if reg.number != 'cfa']
    candidates = function.parameters + function.variables + regs
    logging.debug(f"Function {function.name}@{function.start} has {len(candidates)} potential stack elements.")
    return [stkElm for stkElm in candidates if any(getStackLocations(stkElm))]

def getMaxStackOff(stkElm): # maximal stack offset for a single element
    stkLocs = getStackLocations(stkElm)
    logging.debug(f"Stack element {stkElm} has {len(stkLocs)} stack locations (there might be more non-stack locations for this object).")
    return max(map(lambda stkLoc : abs(stkLoc.expr[1]), stkLocs))

# stkElm can be Register, LocalVariable, or Parameter
def getStackLocations(stkElm):
    return [loc for loc in stkElm.locations if locExprHasOffset(loc)]

def locExprHasOffset(location): # TODO y0 d4wg, this sh!t is sketchy as f*&^
    if location.type in [LocationType.STATIC_GLOBAL, LocationType.STATIC_LOCAL]:
        return len(location.expr) > 1 and type(location.expr[1]) == int
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
            logging.warn(f"Label generation for {func.name} is not sound (got {frame} by offset, but {sum(label)} by size: {label})!")
            #continue # TODO: previously, we included these in the training
        logging.info(f"{func.name} ({frame} by offset / {sum(label)} by size) => {label}")
        allLabels[func.name] = {}
        allLabels[func.name]['inp'] = func.code #' '.join(map(lambda t : t[1], func.code))
        allLabels[func.name]['max'] = frame
        allLabels[func.name]['out'] = label
    return allLabels

def collectOpcodes(func_dict, elf):
    '''pyelftools standalone opcode retrieval (should be fast)'''
    from elftools.elf.constants import SH_FLAGS
    # inspired by 'readelf -x'
    code_sections = {}
    for section in elf.iter_sections():
        if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
            start = section['sh_addr']
            end   = start + section['sh_size']
            if start < end:
                code_sections[(start, end)] = section
    if len(code_sections) == 0:
        logging.critical("File has no executable sections!")
        return func_dict
    for func in func_dict.values():
        if func.is_inline:
            continue
        for section_start, section_end in code_sections.keys():
            if section_start <= func.start <= section_end:
                section = code_sections[(section_start, section_end)]
                if func.start%section['sh_addralign'] != 0:
                    logging.warn(f"Function {func.name}@{hex(func.start)} does not adhere to section alignment.")
                start_off = func.start - section_start
                end_off   = func.start + func.size - section_start
                func._code = section.data()[start_off:end_off+1]
                break
        if func.code is None:
            logging.critical(f"Symbol {func.name}@{hex(func.start)} undefined, opcodes missing!")
    return func_dict

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

# SLOW: Unused, can be removed at some point.
def collectDisassemblyObjdump(functions, filepath):
    import subprocess
    logging.info('Trying to collect function disassembly via objdump..')
    filedisas = subprocess.getoutput(f"objdump -r -j .text -d {filepath}")
    cut1, cut2 = "cut -d: -f2", "awk -F'\t' '{print $2}'"
    procs = [] # subprocesses run in parallel
    for func in functions: # we use awk for cut2 since cut doesn't like Python's TAB insertion
        function = f"awk -v RS= '/^[[:xdigit:]]+ <{func.name}>/'"
        proc = subprocess.Popen(' | '.join([function, cut1, cut2]), shell=True, \
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=bytes(filedisas, encoding='utf-8'))
        if len(err) != 0:
            logging.warn(f"Error during disassembly of {func.name}: " + err.decode('utf-8'))
        lines = out.decode('utf-8').strip().split('\n')
        func._code = ' '.join(map(lambda s : s.replace(' ', ''), lines))
    for p in procs:
        p.wait() # wait for all of them before returning
    return functions

# SUPER SLOW: Unused, can be removed at some point.
def collectDisassemblyGDB(gdbmi, functions, debugFilepath):
    logging.info('Trying to collect function disassembly via GDB..')
    disasQueries = [f'disas /r {func.name}' for func in functions]
    gdbOut = staticGDB(gdbmi, debugFilepath, functions, disasQueries)
    for disas, func in zip(gdbOut, functions):
        func._code = [tuple(line.strip().split('\\t')) for line in disas[1:-1]]
    return functions

# SUPER SLOW: use GDB for validation only
def validateWithGDB(functions, filepath, _gdbmi):
    '''Collects the same info we parsed from .eh_frames section manually using GDB's output for validation.'''
    from pygdbmi.gdbcontroller import GdbController
    logging.info("Attempting to validate frame size and stack symbolization info using GDB..")
    if _gdbmi is None:
        _gdbmi = GdbController() 
    functions = collectLocals(_gdbmi, functions, filepath)
    functions = collectDisassembly(_gdbmi, functions, filepath)
    if _gdbmi is None:
        _gdbmi.exit()
    return functions

# SUPER SLOW: collects function locals via GDBs 'info scope function' command
def collectLocalsGDB(gdbmi, functions, debugFilepath):
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

# SUPER SLOW
def staticGDB(gdbmi, filepath, functions, queries):
    """Obtains additional info about stack variables from GDB (w/o running the binary)."""
    logging.info(f"Loading {filepath} statically in GDB.")
    result = [gdbmi.write(f"-file-exec-and-symbols {filepath}")]
    for q in queries:
        result += [[msg["payload"] for msg in gdbmi.write(q) if msg["type"]=="console"]]
    return result[1:] # skip meta output
