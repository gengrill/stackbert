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
    ADDRINT entryAddr;
    ADDRINT espEntry;
    int maxDiff;
} CallStackEntry;

map<ADDRINT, set<ADDRINT>> boundaryAddrs;
map<ADDRINT, set<ADDRINT>> interestingFunctionAddrs;
map<ADDRINT, bool> exitAddrs;
map<ADDRINT, int> maxObservedSize;
map<ADDRINT, string> funcNames;
map<ADDRINT, bool> bbAddrs;

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

    // Is this necessary? This is just checking if the instruction that
    // we end up at is verified by static disass
    auto foundMember = interestingFunctionAddrs[currentEntry].find(ip);
    if (foundMember == interestingFunctionAddrs[currentEntry].end()) {
        return;
    }

    int currentDiff = topEntry.espEntry - sp;
    topEntry.maxDiff = std::max(topEntry.maxDiff, currentDiff);
    // cerr << std::hex << ip << ":" << std::dec << topEntry.maxDiff << endl;
}

static VOID updateCallStackAtEntry(ADDRINT ip, ADDRINT sp) {
    CallStackEntry entry;
    entry.entryAddr = ip;
    entry.espEntry = sp;
    entry.maxDiff = 0;

    callStack.push(entry);
    // cerr << "Entry into : " << std::hex << ip << endl;
    // cerr << std::hex << ip << endl;
    // cerr << "** " << callStack.size() << " **" << endl;
}

static VOID updateCallStackAtExit(ADDRINT ip, ADDRINT sp, BOOL isTail) {
    if (callStack.empty()) {
        return;
    }

    auto topEntry = callStack.top();
    auto foundExit = boundaryAddrs[topEntry.entryAddr].find(ip);
    if (foundExit == boundaryAddrs[topEntry.entryAddr].end()) {
        // cerr << "**** START ****" << endl;
        // cerr << "0x" << std::hex << ip << ": 0x" << topEntry.entryAddr << endl;
        // while (!callStack.empty()) {
        //     topEntry = callStack.top();
        //     cerr << "0x" << std::hex << topEntry.entryAddr << endl;
        //     callStack.pop();
        // }
        // cerr << "**** END ****" << endl;
        // exit(0);
        return;
    }

    auto foundSize = maxObservedSize.find(topEntry.entryAddr);
    if (foundSize != maxObservedSize.end()) {
        maxObservedSize[topEntry.entryAddr] = std::max(foundSize->second, topEntry.maxDiff);
    } else {
        maxObservedSize[topEntry.entryAddr] = topEntry.maxDiff;
    }

    if (topEntry.espEntry == sp) {
        callStack.pop();
    } else {
        cerr << std::hex << "0x" << topEntry.entryAddr << ":0x" << ip << endl;
    }
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

        INS_InsertCall(ins, where, (AFUNPTR)addStackUpdateEntry, IARG_REG_VALUE, REG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

VOID CallMonitor(INS ins, VOID *v) {
    ADDRINT ip = INS_Address(ins);

    auto foundEntry = boundaryAddrs.find(ip);
    if (foundEntry != boundaryAddrs.end()) {
        // cerr << std::hex << ip << endl;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)updateCallStackAtEntry, IARG_REG_VALUE, REG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
        
    // For some functions which have a single instruction, we need to ensure that we remove them off the callstack
    // as soon as they are added
    auto foundExit = exitAddrs.find(ip);
    if (foundExit != exitAddrs.end()) {
        // cerr << std::hex << ip << endl;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)updateCallStackAtExit, IARG_REG_VALUE, REG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_BOOL, foundExit->second, IARG_END);
    }
}

VOID ParseAddrs() {
    string line, name;
    ADDRINT entryAddr, exitAddr, memberAddr, bbAddr;
    ADDRINT flag, exitType;

    std::ifstream infile(KnobInputFile.Value().c_str());
    while (std::getline(infile, line)) {
        istringstream temp(line, istringstream::in);
        temp >> flag;
        
        if (flag == 0) {
            temp >> entryAddr;
            // cerr << "Entry: " << std::hex << entryAddr << endl;
            boundaryAddrs[entryAddr] = set<ADDRINT>();
            interestingFunctionAddrs[entryAddr] = set<ADDRINT>();
        } else if (flag == 2) {
            temp >> exitAddr;
            temp >> exitType;
            boundaryAddrs[entryAddr].insert(exitAddr);
            // True if it is a tailcall or jmp based call out of a function
            if (exitType == 0) {
                exitAddrs[exitAddr] = false;
            } else {
                exitAddrs[exitAddr] = true;
            }
        } else if (flag == 1) {
            temp >> memberAddr;
            interestingFunctionAddrs[entryAddr].insert(memberAddr);
        } else if (flag == 3) {
            temp >> name;
            funcNames[entryAddr] = name;
        } else if (flag == 4) {
            temp >> bbAddr;
            bbAddrs[bbAddr] = true;
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
