# Sky LZ Decoder
from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import struct
import sys
import os
#import weakref

import gc
#ws = weakref.WeakSet()

def decodeLZ(input):    
    outLength = struct.unpack("<L", input[4:8])
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    #ws.add(mu)

    # Setup the memory for LZ decoding
    mu.mem_map(0x10000, 0x10000, UC_PROT_EXEC) # code

    mu.mem_map(0x60000, 0x40000) # stack    

    inPadding = 1024 - (len(input) % 1024) if len(input) % 1024 else 0
    outPadding = 1024 - (outLength[0] % 1024) if outLength[0] % 1024 else 0    

    OUT_ADDRESS = 0x100000 + (len(input) + inPadding)

    mu.mem_map(0x100000, len(input) + inPadding) # input
    mu.mem_map(OUT_ADDRESS, outLength[0] + outPadding) # output

    #mu.mem_map(0x100000, 2*1024*1024)
    
    mu.mem_write(0x10000, open(os.path.dirname(__file__) + "/SkyLZ.so", "rb").read()) # Map the decoder code
    mu.mem_write(0x100000, input) # Map the compressed data

    # initialize machine registers
    mu.reg_write(UC_ARM_REG_R0, 0x100000) # Input
    mu.reg_write(UC_ARM_REG_R1, OUT_ADDRESS) # Output
    mu.reg_write(UC_ARM_REG_R2, len(input)) # Length
    #mu.reg_write(UC_ARM_REG_APSR, 0x0)
    mu.reg_write(UC_ARM_REG_SP, 0x80000) # Stack
    #mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on
    #mu.reg_write(UC_ARM_REG_CPSR, (1 << 6))

    #
    #mu.

    def hook_block(uc, address, size, user_data):                
        if address >= 0x0 and address < 0x10000: 
            uc.emu_stop()        

    def hook_invalid(uc, access, address, size, value, user_data):        
        #print(hex(address))
        mu.mem_map(address, 1024)
        return True

    # tracing all basic blocks with customized callback
    mu.hook_add(UC_HOOK_BLOCK, hook_block)   
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)            
    
    # emulate machine code in infinite time
    mu.emu_start(0x13141, 0x13140+0x800)

    outp = mu.mem_read(OUT_ADDRESS, outLength[0])
    
    '''
    for f in mu.mem_regions():
        print(f[0], f[1])
        mu.mem_unmap(f[0], f[1])
    '''

    gc.collect()
    return outp

if __name__ == "__main__":
    from PIL import Image
    data = decodeLZ(open(sys.argv[1], "rb").read())  
    open(sys.argv[2], "wb").write(data)
    