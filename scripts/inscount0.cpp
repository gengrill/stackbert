/*
 * Copyright 2002-2020 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <set>
#include <string>
#include <stack>
#include "pin.H"

using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
using std::map;
using std::set;
using std::istringstream;
using std::stack;

ofstream OutFile;

typedef struct {
    UINT32 entryAddr;
    UINT32 espEntry;
    UINT32 maxDiff;
} CallStackEntry;

map<ADDRINT, set<ADDRINT>> boundaryAddrs;
map<ADDRINT, set<ADDRINT>> interestingFunctionAddrs;
map<ADDRINT, bool> exitAddrs;
map<ADDRINT, UINT32> maxObservedSize;
map<ADDRINT, string> funcNames;

stack<CallStackEntry> callStack;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "stackSizes.out", "specify output file name");

KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "addrs.txt", "specify input file name");

// This function is called before every instruction is executed
static VOID addStackUpdateEntry(ADDRINT ip, ADDRINT sp) { 
    if (callStack.empty()) {
        return;
    }

    CallStackEntry &topEntry = callStack.top();
    ADDRINT currentEntry = topEntry.entryAddr;

    auto foundMember = interestingFunctionAddrs[currentEntry].find(ip);
    if (foundMember == interestingFunctionAddrs[currentEntry].end()) {
        return;
    }

    UINT32 currentDiff = topEntry.espEntry - sp;
    topEntry.maxDiff = std::max(topEntry.maxDiff, currentDiff);
    // cerr << std::hex << ip << ":" << std::hex << topEntry.maxDiff << endl;
}

static VOID updateCallStackAtEntry(ADDRINT ip, ADDRINT sp) {
    CallStackEntry entry;
    entry.entryAddr = ip;
    entry.espEntry = sp;
    entry.maxDiff = 0;

    callStack.push(entry);
    // cerr << std::hex << ip << endl;
    // cerr << callStack.size() << endl;
}

static VOID updateCallStackAtExit(ADDRINT ip, ADDRINT sp) {
    if (callStack.empty()) {
        return;
    }

    auto topEntry = callStack.top();
    auto foundExit = boundaryAddrs[topEntry.entryAddr].find(ip);
    if (foundExit == boundaryAddrs[topEntry.entryAddr].end()) {
        return;
    }

    auto foundSize = maxObservedSize.find(topEntry.entryAddr);
    if (foundSize != maxObservedSize.end()) {
        maxObservedSize[topEntry.entryAddr] = std::max(foundSize->second, topEntry.maxDiff);
    } else {
        maxObservedSize[topEntry.entryAddr] = topEntry.maxDiff;
    }
    callStack.pop();
}

// Pin calls this function every time a new instruction is encountered
VOID StackMonitor(INS ins, VOID *v)
{
    if (INS_RegWContain(ins, REG_STACK_PTR) ||
        INS_Category(ins) == XED_CATEGORY_CALL ||
        INS_Category(ins) == XED_CATEGORY_PUSH ||
        INS_Category(ins) == XED_CATEGORY_POP ||
        INS_Category(ins) == XED_CATEGORY_RET) {

        if (INS_IsSysenter(ins)) return;

        IPOINT where = INS_IsValidForIpointAfter(ins) ? IPOINT_AFTER : IPOINT_TAKEN_BRANCH;

        // cerr << std::hex << INS_Address(ins) << endl;

        INS_InsertCall(ins, where, (AFUNPTR)addStackUpdateEntry, IARG_REG_VALUE, REG_EIP, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

VOID CallMonitor(INS ins, VOID *v) {
    ADDRINT ip = INS_Address(ins);

    auto foundEntry = boundaryAddrs.find(ip);
    if (foundEntry != boundaryAddrs.end()) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)updateCallStackAtEntry, IARG_REG_VALUE, REG_EIP, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    } 
        
    // For some functions which have a single instruction, we need to ensure that we remove them off the callstack
    // as soon as they are added
    auto foundExit = exitAddrs.find(ip);
    if (foundExit != exitAddrs.end()) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)updateCallStackAtExit, IARG_REG_VALUE, REG_EIP, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

VOID ParseAddrs() {
    string line, name;
    UINT32 entryAddr, exitAddr, memberAddr;
    ADDRINT flag;

    std::ifstream infile(KnobInputFile.Value().c_str());
    while (std::getline(infile, line)) {
        istringstream temp(line, istringstream::in);
        temp >> flag;
        
        if (flag == 0) {
            temp >> entryAddr;
            // cerr << "Entry: " << std::hex << entryAddr << endl;
            boundaryAddrs[entryAddr] = set<UINT32>();
            interestingFunctionAddrs[entryAddr] = set<UINT32>();
        } else if (flag == 1) {
            temp >> exitAddr;
            // cerr << "Exit: " << std::hex << exitAddr << endl;
            boundaryAddrs[entryAddr].insert(exitAddr);
            exitAddrs[exitAddr] = true;
        } else if (flag == 2) {
            temp >> memberAddr;
            interestingFunctionAddrs[entryAddr].insert(memberAddr);
        } else if (flag == 3) {
            temp >> name;
            funcNames[entryAddr] = name;
        }
    }

    cerr << "======================" << endl;
    cerr << "Parsing of addrs done!" << endl;
    cerr << "======================" << endl;
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    ofstream result;
    result.open(KnobOutputFile.Value().c_str());
    for (auto& addrPair : maxObservedSize) {
        result << funcNames[addrPair.first] << ":" << addrPair.second << endl;
    }
    result.close();

    cerr << "======================" << endl;
    cerr << "Execution done" << endl;
    cerr << "======================" << endl;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts max stack runtime stack size per function." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register StackMonitor to be called when checking stack updates
    INS_AddInstrumentFunction(StackMonitor, 0);

    // Register CallMonitor to be called at function starts and ends
    INS_AddInstrumentFunction(CallMonitor, 0);

    ParseAddrs();

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
