import ctypes
import os

dll = None

try:
    dll = ctypes.CDLL(os.path.dirname(__file__) + "/minilzo.x64.dll")
except Exception:
    dll = ctypes.CDLL(os.path.dirname(__file__) + "/minilzo.x86.dll")

_lzo_decomp = dll.lzo1x_decompress_safe

_lzo_decomp.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_int)]
_lzo_decomp.restype = ctypes.c_int

def decompress(data, output_size):
    input_data = (ctypes.c_ubyte * len(data)).from_buffer(bytearray(data))
    output_data = (ctypes.c_ubyte * output_size)()

    out_tot = ctypes.c_int(output_size)

    ret = _lzo_decomp(input_data, len(data), output_data, out_tot)
    
    if ret not in [0, -8]: raise Exception(f"Decompress fail: " + str(ret))    

    return bytes(output_data)[:out_tot.value]

'''
if __name__ == "__main__":
    z = open("newlz.bin", "rb").read()    

    input_data = (ctypes.c_ubyte * len(z)).from_buffer(bytearray(z))
    output_data = (ctypes.c_ubyte * 0x20000)()

    ret = _lzo_decomp(input_data, len(z), output_data, ctypes.c_int(0))

    print(ret)
    open("sfp", "wb").write(output_data)
'''