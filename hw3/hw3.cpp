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

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

VOID docount() { ins_count++; }

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

VOID RecordMemWriteBefore(VOID * ip, VOID * addr, UINT32 size)
{
    fprintf(DBG_LOG, "[MEMWRITE(BEFORE)] %p, memaddr: %p, size: %d\n", ip, addr, size);
    unsigned char* p = (unsigned char*)addr;
    for( unsigned  int i = 0; i < size; i++ ) {
        fprintf(DBG_LOG, "%02x ", (unsigned char)*p);
        p++;
    }
    fprintf(DBG_LOG, "\n");
}

VOID RecordMemWriteAfter(VOID * ip, VOID * addr, UINT32 size)
{
    fprintf(DBG_LOG, "[MEMWRITE(AFTER)] %p, memaddr: %p, size: %d\n", ip, addr, size);
    unsigned char* p = (unsigned char*)addr;
    for( unsigned  int i = 0; i < size; i++ ) {
        *p = 0;
        fprintf(DBG_LOG, "%02x ", (unsigned char)*p);
        p++;
    }
    fprintf(DBG_LOG, "\n");
}


VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size)
{
    fprintf(DBG_LOG, "[MEMREAD] %p, memaddr: %p, size: %d\n", ip, addr, size);
    unsigned char* p = (unsigned char*)addr;
    for( unsigned  int i = 0; i < size; i++ ) {
        fprintf(DBG_LOG, "%02x ", (unsigned char)*p);
        p++;
    }
    fprintf(DBG_LOG, "\n");
}

VOID RecordMemCollide(VOID * ip, VOID * addr, UINT32 size, ADDRINT* regRSP)
{
    //ADDRINT offset = (ADDRINT)ip - g_addrLow;
    if (0x555555590160 == (ADDRINT)addr) {
        // collide
        fprintf(DBG_LOG, "[Collide] %p, memaddr: %p, size: %d\n", ip, addr, size);
        memset(addr, 0 ,size);
    }

/*     if (0x7fffffffd868 == (ADDRINT)addr) {
        // over
        fprintf(DBG_LOG, "[Over] %p, memaddr: %p, size: %d\n", ip, addr, size);
        memset(addr, 0 ,size);
    } */
}

VOID RecordMemCollide2(VOID * ip, VOID * addr, UINT32 size, ADDRINT* regRSP)
{
    //ADDRINT offset = (ADDRINT)ip - g_addrLow;
    if (0x7fffffffd8ac == (ADDRINT)addr) {
        // collide
        fprintf(DBG_LOG, "[CollideReset] %p, memaddr: %p, size: %d\n", ip, addr, size);
        memset(addr, 0 ,size);
    }
}


VOID RecordCollisionCall(VOID * ip, VOID * addr, UINT32 size)
{
    fprintf(DBG_LOG, "[CollideCheck] %p, memaddr: %p, size: %d\n", ip, addr, size);
}

VOID Instruction(INS ins, VOID* v) { 
    string strInst = INS_Disassemble(ins);
    ADDRINT addr = INS_Address(ins);

    if( g_bMainExecLoaded ) {
        if( g_addrLow <= addr && addr <= g_addrHigh ) {
            // fprintf( DBG_LOG, "[%lx] %s\n", addr - g_addrLow, strInst.c_str());
            const char* operation = strInst.c_str();
            if ( strstr(operation, "push r") == operation) {
                return ;
            }
#if 0
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
                                ins, IPOINT_AFTER, (AFUNPTR)RecordMemCollide2,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYWRITE_SIZE,
                                IARG_REG_REFERENCE, REG_RSP,
                                IARG_END);
                        }
                    }
            }  
#endif
#if 1
            ADDRINT offset = addr - g_addrLow;
            if( 
                (offset == 0x1f09) || (offset == 0x1d8e) || (offset == 0x1fb6)
                //(offset == 0x1cc9) // method 2
                ) {
                UINT32 memOperands = INS_MemoryOperandCount(ins);
                for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                    {
                        if (INS_OperandIsImplicit(ins, memOp))
                        {
                            continue;
                        }
                        // Note that in some architectures a single memory operand can be 
                        // both read and written (for instance incl (%eax) on IA-32)
                        // In that case we instrument it once for read and once for write.
                        if (INS_MemoryOperandIsWritten(ins, memOp))
                        {
                            INS_InsertCall(
                                ins, IPOINT_AFTER, (AFUNPTR)RecordCollisionCall,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYWRITE_SIZE,
                                IARG_END);

                        }
                    }
            }
#endif
#if 0
            if( (offset == 0x1f09) || (offset == 0x1d8e) ) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EveryInst, IARG_INST_PTR, 
                                    IARG_REG_REFERENCE, REG_RAX, 
                                    IARG_REG_REFERENCE, REG_RBX, 
                                    IARG_REG_REFERENCE, REG_RCX, 
                                    IARG_REG_REFERENCE, REG_RDX, 
                                    IARG_END); 
            }
#endif
#if 0
            else if (offset == 0x1dcb)
            {
                    UINT32 memOperands = INS_MemoryOperandCount(ins);
                    // Iterate over each memory operand of the instruction.
                    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                    {
                        if (INS_MemoryOperandIsRead(ins, memOp))
                        {
                            INS_InsertCall(
                                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYREAD_SIZE,
                                IARG_END);
                        }
                        // Note that in some architectures a single memory operand can be 
                        // both read and written (for instance incl (%eax) on IA-32)
                        // In that case we instrument it once for read and once for write.
                        if (INS_MemoryOperandIsWritten(ins, memOp))
                        {
                            INS_InsertCall(
                                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWriteBefore,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYWRITE_SIZE,
                                IARG_END);
                            INS_InsertCall(
                                ins, IPOINT_AFTER, (AFUNPTR)RecordMemWriteAfter,
                                IARG_INST_PTR,
                                IARG_MEMORYOP_EA, memOp,
                                IARG_MEMORYWRITE_SIZE,
                                IARG_END);

                        }
                    }
            }
#endif            
        }
    }

    // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END); 
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) { cerr << "Count " << ins_count << endl; }

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    DBG_LOG = fopen("loghw3.txt", "wt");

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
