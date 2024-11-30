import struct
import os
import sys
from PIL import Image

if len(sys.argv) < 2:
	print(f"Not enough arguments! usage: {sys.argv[0]} file", file=sys.stderr)
	sys.exit(1)

sz = os.path.getsize(sys.argv[1])
fd = open(sys.argv[1], "rb")
index = 0
if not os.path.exists(f"{sys.argv[1]}_EXT"):
	os.makedirs(f"{sys.argv[1]}_EXT", exist_ok=True)
#get offs
fd.seek(sz-4) 
tbl_offs = struct.unpack("<L", fd.read(4))[0]
fd.seek(tbl_offs+16)
while fd.tell() < sz:
	idx, part = struct.unpack("<HH", fd.read(4))
	if idx == 1 and part == 0:
		fd.seek(tbl_offs+16)
	if idx == 0 and part == 0:
		break
	type, foffs, fnoffs = struct.unpack("<LLL", fd.read(12))
	ssz =  struct.unpack("<L", fd.read(4))[0]
	if part == 2: #IM-U160K PDL tbl: part == 2 -> 0x2000 hash, may be skipped by flasher?
		foffs += 0x2000
		ssz -= 0x2000
	fd.read(20)
	b_info, ver_info = struct.unpack("<LL", fd.read(8))
	sname_x = fd.read(48)
	c_off = fd.tell()
	null_idx = sname_x.find(b'\x00')
	sname_ex = sname_x[:null_idx].decode('euc-kr')
	print(f"Stage {part} Item {idx} -> {sname_ex}, type {type}, from {hex(foffs)} size {ssz} write to flash in {hex(fnoffs)}")
	fd.seek(foffs)
	open(f"{sys.argv[1]}_EXT/{part}_{idx}_{sname_ex}_{hex(fnoffs)}.bin", "wb").write(fd.read(ssz))
	fd.seek(c_off)
