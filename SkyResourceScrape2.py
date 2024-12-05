import struct
import os
import sys
from io import BytesIO
import SkyLZ

blk_size = 512

if len(sys.argv) < 3:
	print(f"Not enough arguments! usage: {sys.argv[0]} file offset", file=sys.stderr)
	sys.exit(1)

sz = os.path.getsize(sys.argv[1])
fd = open(sys.argv[1], "rb")
offs = int(sys.argv[2], 16)
fd.seek(offs)

folder_path = os.path.split(os.path.abspath(sys.argv[1]))[0]
out_path = f"{folder_path}/Out"

if not os.path.exists(out_path):
	os.makedirs(out_path, exist_ok=True)

size, unk1, unk2, items = struct.unpack("<LLLL", fd.read(16))
tbl_items = BytesIO(fd.read(16*items))
csv_is_open = False
folder_path = os.path.split(os.path.abspath(sys.argv[1]))[0]
itm = 0
while itm < items:
	item_no, type, toffs, size = struct.unpack("<LLLL", tbl_items.read(16))
	if item_no == 0 and type == 0:
		if (itm+1) >= items:
			break
		tbl_items.read(16)
		itm += 2
	else:
		fd.seek(toffs+offs)
		data = fd.read(size)
		if data[0:3] == b"FWS":
			ext = "swf"
		elif struct.unpack(">H", data[0:2])[0] & 0xFF80 == 0xFF80 or struct.unpack(">H", data[0:2])[0] & 0xFF80 == 0xFF00:
			ext = "aac"
		elif data[0:4] == b"MMMD":
			ext = "mmf"
		elif data[20:28] == b"ftyp3gp4":
			data = data[16:]
			ext = "3gp"
		elif struct.unpack("<H", data[0:2])[0] == 4: #assume its SKY LZ
			data = SkyLZ.decodeLZ(data)  
			ext = "bin"
		else:
			ext = "bin"
		open(f"{out_path}/{item_no}.{ext}", "wb").write(data)
		itm += 1
		