from __future__ import print_function
import sys
import typing
import struct
from PIL import Image
from miniLZO import miniLZO

def rgb24Convert(data):
    offset = 0
    out_temp = bytearray()

    while offset<len(data):
        curUPByte = struct.unpack("<L", data[offset:offset+4])[0]         

        r, g, b = (curUPByte >> 12) & 0x3f, (curUPByte >> 6) & 0x3f, curUPByte & 0x3f
        out_temp += struct.pack("<BBB", int(r  * 4.0476190476190474),int(g  * 4.0476190476190474),int(b * 4.0476190476190474))
        offset += 4

    return bytes(out_temp)
    
def decompress(data: typing.Union[bytes, bytearray, str], out_size: int):
    if type(data) == str:
        data = open(data, "rb").read()    

    return miniLZO.decompress(bytes(data), out_size)

def decodeFrame2(data: typing.Union[bytes, bytearray, str]):
    if type(data) == str:
        data = open(data, "rb").read()
    assert data[:2] == b"CF", "Not a valid Pantech CF Image."
    width, height, bpp, bits, ctype, size = struct.unpack("<HHBBBH", data[0x2:0xb])
    offset = 0xb
    
    block_encoding = bool(ctype & 0x1)
    pal_comp = bool(ctype >> 1 & 0x1)
    map_comp = bool(ctype >> 2 & 0x1)

    if block_encoding == True:
        temp = Image.new("RGB", (width, height))
        
        palettes = []
        
        if pal_comp == True:
            pal_comp_size = struct.unpack("<H", data[offset:offset+2])[0]
            pal_data = decompress(data[offset+2:offset+2+pal_comp_size], size*8)
            offset += 2+pal_comp_size
        else:
            pal_data = data[offset:offset+(size*8)]
            offset += size*8
            
        if map_comp == True:
            map_comp_size = struct.unpack("<H", data[offset:offset+2])[0]
            map_data = decompress(data[offset+2:offset+2+map_comp_size], (width*height))
            offset += 2+map_comp_size
        else:
            map_data = data[offset:offset+(width*height)]
            offset += (width*height)
        
        offset = 0

        for p in range(size):            
            palettes.append(pal_data[(p*8):(p*8)+8])  

        for y in range(0, height, 2):
            for x in range(0, width, 2):                
                pixel = Image.frombytes("RGB", (2,2), palettes[min(struct.unpack("<H", map_data[offset:offset+2])[0], size-1)], "raw", "BGR;16", 0, 1) 
                temp.paste(pixel, (x,y))
                offset += 2
                
        return temp
    else:
        data = decompress(data[offset:offset+size+0x80000], (width*height)*4)
        return Image.frombytes("RGBA", (width, height), data, "raw", "BGRA", 0, 1) if bits == 0x3 else Image.frombytes("RGB", (width, height), data, "raw", "BGR;16", 0, 1)
    
def decodeFrame1(data: typing.Union[bytes, bytearray, str]):
    if type(data) == str:
        data = open(data, "rb").read()
    assert data[:2] == b"PC", "Not a valid Pantech PC Image."
    if data[2] == 0:        
        return decompress(data[5:5+(struct.unpack("<H", data[3:5])[0])], 0x800000)
    
    else:
        pType, width, height, pSize, pcSize = struct.unpack("<BBBHH", data[0x2:0x9])        

        if pType == 0x1:
            temp = Image.new("RGB", (width, height))
            
            offset = 0x7

            palettes = []
            for _ in range(pSize):
                palettes.append(data[offset:offset+8])
                offset += 8
                    
            for y in range(0, height, 2):
                for x in range(0, width, 2):                
                    pixel = Image.frombytes("RGB", (2,2), palettes[min(struct.unpack("<H", data[offset:offset+2])[0], pSize-1)], "raw", "BGR;16", 0, 1) 
                    temp.paste(pixel, (x,y))
                    offset += 2                
                
            return temp
        
        elif pType == 0x7:            
            temp = Image.new("RGB", (width, height))
                                
            pTemp = decompress(data[0x9:0x9+pcSize], pSize*8)            
            dSize = struct.unpack("<H", data[0x9+pcSize:0x9+pcSize+2])[0]        
            dData = decompress(data[0x9+pcSize+2:0x9+pcSize+2+dSize], (width*height))

            palettes = []
            for p in range(pSize):            
                palettes.append(pTemp[(p*8):(p*8)+8])        

            offset = 0 

            for y in range(0, height, 2):
                for x in range(0, width, 2):                
                    pixel = Image.frombytes("RGB", (2,2), palettes[min(struct.unpack("<H", dData[offset:offset+2])[0], pSize-1)], "raw", "BGR;16", 0, 1) 
                    temp.paste(pixel, (x,y))
                    offset += 2

            return temp

        else:
            raise Exception(f"Unknown PC type: {pType}")

class AF():
    def __init__(self, data: typing.Union[bytes, bytearray, str]):
        if type(data) == str:
            data = open(data, "rb").read()
        assert data[:2] == b"AF", "Not a valid Pantech AF Image."        
        self.width, self.height, self.bpp, self.bits, self.frames = struct.unpack("<HHBBH", data[0x2:0xa])

        self._data = data        
        self._frames = []

        if data[0xa] == 0x0:
            pSize = struct.unpack("<L", data[0xb:0xf])[0]
            assert pSize <= 0xfffff, "Overflow"

            self._palettes = []
            offset = 0xf

            for _ in range(pSize):
                self._palettes.append(data[offset:offset+8])
                offset += 0x8
        
            self._frames = []

            for _ in range(self.frames):
                self._frames.append(struct.unpack("<BLH", data[offset:offset+7]))
                offset += 7

        elif data[0xa] == 0x2:
            pSize = struct.unpack("<L", data[0xb:0xf])[0]
            pData = decompress(data[0xf:0xf+pSize], 0x80000)

            self._palettes = []

            for i in range(0x10000):
                self._palettes.append(pData[(i*8):(i*8)+8])                        

            offset = 0xf+pSize
            for _ in range(self.frames):
                self._frames.append(struct.unpack("<BLH", data[offset:offset+7]))
                offset += 7

        elif data[0xa] == 0x20:
            offset = 0xf
            dataOffset = 0xf + (self.frames*4)
            
            for _ in range(self.frames):
                imgSize = struct.unpack("<L", data[offset:offset+4])[0]
                self._frames.append((2, dataOffset, imgSize))
                offset += 4
                dataOffset += imgSize

        else:
            raise Exception("Unimplemented feature: pcType other than 0x0, 0x2 and 0x20")
    def get(self, frame: int):
        temp = Image.new("RGB", (self.width, self.height))
        isCompressed, offset, size = self._frames[frame]

        fData = self._data[offset:offset+size]

        if isCompressed == 2:
            fData = decompress(fData, (self.width*self.height)*4)

        elif isCompressed == 1:                                         
            fData = decompress(fData, (self.width*self.height))

        if isCompressed == 2:
            return Image.frombytes("RGBA", (self.width, self.height), fData, "raw", "BGRA", 0, 1) if self.bits == 0x3 else Image.frombytes("RGB", (self.width, self.height), fData, "raw", "BGR;16", 0, 1)
        
        elif isCompressed in [0, 1]:
            offset = 0

            for y in range(0, self.height, 2):
                for x in range(0, self.width, 2):                
                    pixel = Image.frombytes("RGB", (2,2), self._palettes[struct.unpack("<H", fData[offset:offset+2])[0]], "raw", "BGR;16", 0, 1) 
                    temp.paste(pixel, (x,y))
                    offset += 2

            return temp
        
    def __iter__(self):
        self._curFrame = 0
        return self
    
    def __next__(self):
        if self._curFrame >= len(self._frames): raise StopIteration()
        
        #print(self._curFrame)
        frame = self.get(self._curFrame)
        self._curFrame += 1

        return frame
    
class AP():
    def __init__(self, data: typing.Union[bytes, bytearray, str]):
        if type(data) == str:
            data = open(data, "rb").read()
        assert data[:2] == b"AP", "Not a valid Pantech AP Image."        
        self.type, self.frames, self.width, self.height, self.palettes = struct.unpack("<BBBBL", data[0x2:0xa])

        assert self.frames > 0, "Empty frames"
        assert self.palettes <= 0xfffff or self.type == 0x20, "Overflow"

        self._palettes = []
        offset = 0xa
        
        if self.type in [2, 0xa]:
            self._tPalette = decompress(data[offset:offset+self.palettes], 0x100000)

            offset_t = 0
            while offset_t<len(self._tPalette):
                self._palettes.append(self._tPalette[offset_t:offset_t+(0x8 if self.type == 2 else 0x10)])
                offset_t += 0x8 if self.type == 2 else 0x10

            offset += self.palettes

        elif self.type == 0:            
            for _ in range(self.palettes):
                self._palettes.append(data[offset:offset+8])
                offset += 0x8

        elif self.type == 0x20:
            pass

        else:
            raise Exception(f"Unknown codec type: {hex(self.type)}")
    
        self._frames = []

        if self.type == 0x20:
            offset = 6
            for _ in range(self.frames):
                self._frames.append((1, (6+(4*self.frames)) + struct.unpack("<L", data[offset:offset+4])[0], 0x200000))
                offset += 4

        else:
            for _ in range(self.frames):
                self._frames.append(struct.unpack("<BLH", data[offset:offset+7]))
                offset += 7

        self._data = data

    def get(self, frame: int):
        temp = Image.new("RGB", (self.width, self.height))
        isCompressed, offset, size = self._frames[frame]           

        fData = self._data[offset:offset+size]

        if isCompressed:                                         
            fData = decompress(fData, (self.width*self.height*2))

        if self.type == 0x20:            
            return Image.frombytes("RGB", (self.width, self.height), fData, "raw", "BGR;16", 0, 1) 
        
        else:
            offset = 0

            for y in range(0, self.height, 2):
                for x in range(0, self.width, 2):                
                    pixel = Image.frombytes("RGB", (2,2), self._palettes[struct.unpack("<H", fData[offset:offset+2])[0]], "raw", "BGR;16", 0, 1) if self.type == 2 else Image.frombytes("RGB", (2,2), rgb24Convert(self._palettes[struct.unpack("<H", fData[offset:offset+2])[0]])) 
                    temp.paste(pixel, (x,y))
                    offset += 2

            return temp
        
    def __iter__(self):
        self._curFrame = 0
        return self
    
    def __next__(self):
        if self._curFrame >= len(self._frames): raise StopIteration()
        
        #print(self._curFrame)
        frame = self.get(self._curFrame)
        self._curFrame += 1

        return frame


if __name__ == "__main__":
    decodeFrame2(sys.argv[1]).save(sys.argv[2])


'''
class CF():
    def __init__(self, data: typing.Union[bytes, bytearray, str]):        
        self._parsed = False

        if type(data) == str:
            data = open(data, "rb").read()

        assert data[:2] == b"CF", "Not a valid Pantech CF Image."
        self._width, self._height
    def __init__(data, out_size):
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    heap = ucHeapLib.UnicornSimpleHeap(mu)
    mu.ctl_exits_enabled(True)
    mu.ctl_set_exits([0])

    mu.mem_map(0x0, 16 * 1024 * 1024)    

    mu.mem_map(0xc0000000, 64 * 1024 * 1024)    
    mu.mem_map(0xfe000000, 4 * 1024 * 1024)    

    flashParser.parse(mu, os.path.dirname(__file__) + "/qc-u160k.fls")
    mu.mem_write(0xc0000000, data)

    out_offset = 0xc0000000 + len(data) + 0x10000

    mu.reg_write(UC_ARM_REG_R0, 0x0) # X                          
    mu.reg_write(UC_ARM_REG_R1, 0x0) # Y
    mu.reg_write(UC_ARM_REG_R2, 0x0) # P
    mu.reg_write(UC_ARM_REG_R3, 0xa0000000) # Input        
    mu.mem_write(0xf0200000, struct.pack("<LLLLL", 176, 220, 0xe0010000, 0x80100000, 0x64)) # Width, Height, Output, Exception, Line

    mu.reg_write(UC_ARM_REG_SP, 0xfe040000)
    mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on
        
    # tracing one instruction at ADDRESS with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code, heap)

    def on_read(mu, access, address, size, value, data):
        if DEBUG:
            print("Read at", hex(address), size, mu.mem_read(address, size))

    def on_write(mu, access, address, size, value, data):
        if DEBUG:
            print("Write at", hex(address), size, hex(value))

    def on_error(mu, access, address, size, value, data):
        if DEBUG or True:
            print("Error at", hex(address), size, hex(value))

    mu.hook_add(UC_HOOK_MEM_READ, on_read)
    mu.hook_add(UC_HOOK_MEM_WRITE, on_write)
    mu.hook_add(UC_HOOK_MEM_INVALID, on_error)
    
    for f in MEMCPY_ADDRESS+MALLOC_ADDRESS+FREE_ADDRESS+MEMSET_ADDRESS+CALLOC_ADDRESS+REALLOC_ADDRESS:
        mu.mem_write(f, ARM_RTS_LONG)

    for f in MALLOC_ADDRESS_T+MEMCPY_ADDRESS_T+FREE_ADDRESS_T:
        mu.mem_write(f, ARM_RTS)

    # emulate machine code in infinite time
    mu.emu_start(0x04f47988, 0xc0000000)

    temp = mu.mem_read(out_offset, out_size)

    del mu
    gc.collect()

    return temp
'''