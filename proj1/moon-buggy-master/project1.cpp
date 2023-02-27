/*! @file
 *  This file contains an ISA-portable PIN tool for counting dynamic instructions
 */

#include "pin.H"
#include <iostream>
using std::cerr;
using std::endl;

using namespace std;

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

VOID ModifyCrash(ADDRINT ip, 
               ADDRINT * regRAX, 
               ADDRINT * regRBX,
               ADDRINT * regRCX, 
               ADDRINT * regRDX) 
{
    fprintf(DBG_LOG, "crash modification [%lx] \n", *regRAX); // read value
    *regRAX = 0; // new value
}


VOID Instruction(INS ins, VOID* v) { 
    string strInst = INS_Disassemble(ins);
    ADDRINT addr = INS_Address(ins);

    if( g_bMainExecLoaded ) {
        if( g_addrLow <= addr && addr <= g_addrHigh ) {
            fprintf( DBG_LOG, "[%lx] %s\n", addr - g_addrLow, strInst.c_str());
            ADDRINT offset = addr - g_addrLow;
            if( offset == 0xa7be ) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ModifyCrash, IARG_INST_PTR, 
                                    IARG_REG_REFERENCE, REG_RAX, 
                                    IARG_REG_REFERENCE, REG_RBX, 
                                    IARG_REG_REFERENCE, REG_RCX, 
                                    IARG_REG_REFERENCE, REG_RDX, 
                                    IARG_END); 
            } 
            else if ( offset == 0xb000 ) {
                ADDRINT target = addr + 0x30;
                INS_InsertDirectJump(ins, IPOINT_AFTER, target);
            }      
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

    // Register ImageLoad to be called when an image is loaded
    INS_AddInstrumentFunction(Instruction, 0);

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

