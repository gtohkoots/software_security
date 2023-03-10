/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This file contains an ISA-portable PIN tool for counting dynamic instructions
 */

#include "pin.H"
#include <iostream>
using std::cerr;
using std::endl;

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

UINT64 ins_count = 0;

ADDRINT g_addrLow, g_addrHigh;
BOOL g_bMainExecLoaded = FALSE;
unsigned short g_map[0XFFFF];
FILE* g_fpLog = 0;

#define DBG_LOG g_fpLog

VOID ImageLoad(IMG img, VOID *v)
{
    if( IMG_IsMainExecutable(img) ) {
        g_addrLow = IMG_LowAddress(img); 
        g_addrHigh = IMG_HighAddress(img);
        
        // Use the above addresses to prune out non-interesting instructions.
        g_bMainExecLoaded = TRUE;
        fprintf(DBG_LOG, "Main Exec   : %lx ~ %lx\n",IMG_LowAddress(img), IMG_HighAddress(img));
    }
    else {
        fprintf(DBG_LOG, "Library   : %lx ~ %lx\n",IMG_LowAddress(img), IMG_HighAddress(img));
    }
}

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

int IsStackMem_Heuristic(ADDRINT rsp, ADDRINT mem)

{

    if( (rsp - 0x10000) < mem && mem < (rsp + 0x10000) ) {

        return 1;

    }

    return 0;

}

 

void LogData(VOID* addr, UINT32 size)

{

    switch( size ) {

    case 4:

        {

            unsigned int* pData = (unsigned int*)addr;

            fprintf(DBG_LOG,"%d\n", *pData);

        }

        break;

    case 8:

        {

            unsigned long int* pData = (unsigned long int*)addr;

            fprintf(DBG_LOG,"%ld\n", *pData);

        }

        break;

    default:

        {

            unsigned char* pData = (unsigned char*)addr;

            for( unsigned  int i = 0; i < size; i++, pData++ ) {

                fprintf(DBG_LOG,"%02x ", (unsigned char)*pData);

            }

            fprintf(DBG_LOG,"\n");

        }

        break;

    }

}

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */
VOID EveryInst(ADDRINT ip, 
               ADDRINT * regRAX, 
               ADDRINT * regRBX,
               ADDRINT * regRCX, 
               ADDRINT * regRDX) 
{
    fprintf(DBG_LOG, "[%lx] \n", *regRAX); // read value
    *regRAX = 0; // new value
}

VOID RecordMemWriteAfter(VOID * ip, VOID * addr, UINT32 size, ADDRINT* regRSP)
{
    ADDRINT offset = (ADDRINT)ip - g_addrLow;

    if( IsStackMem_Heuristic(*regRSP, (ADDRINT)addr)){
        return;
    }

    g_map[offset]++;

    fprintf(DBG_LOG,"[MEMWRITE(AFTER)] %lx (hitcount: %d), mem: %p (sz: %d) (stack: %lx) -> ", offset, g_map[offset], addr, size, *regRSP);
    LogData(addr, size);
}


VOID Instruction(INS ins, VOID* v) { 
    string strInst = INS_Disassemble(ins);
    ADDRINT addr = INS_Address(ins);

    if( g_bMainExecLoaded ) {
        if( g_addrLow <= addr && addr <= g_addrHigh ) {
            fprintf( DBG_LOG, "[Read] [%lx] %s\n", addr - g_addrLow, strInst.c_str());
            const char* operation = strInst.c_str();
            if ( strstr(operation, "push r") == operation) {
                return ;
            }
            //ADDRINT offset = addr - g_addrLow;  
            if (INS_IsValidForIpointAfter(ins) == TRUE && INS_IsCall(ins) == FALSE && INS_IsMemoryWrite(ins) == TRUE) {
                    UINT32 memOperands = INS_MemoryOperandCount(ins);
                    // Iterate over each memory operand of the instruction.
                    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                    {
                        if (INS_OperandIsImplicit(ins, memOp)){
                            continue;
                        }
                        // Note that in some architectures a single memory operand can be 
                        // both read and written (for instance incl (%eax) on IA-32)
                        // In that case we instrument it once for read and once for write.
                        if (INS_MemoryOperandIsWritten(ins, memOp))
                        {
                            INS_InsertCall(
                                ins, IPOINT_AFTER, (AFUNPTR)RecordMemWriteAfter,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYWRITE_SIZE,
                                IARG_REG_REFERENCE, REG_RSP,
                                IARG_END);
                        }
                    }
            }      
        }
    }

    // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END); 
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) { 
    for (int i = 0; i< 0XFFFF; i++) {
        if(g_map[i]){
            fprintf(DBG_LOG, "offset: %x hit-count: %d \n", i, g_map[i]);
        }
    }
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    DBG_LOG = fopen("log.txt", "wt");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
