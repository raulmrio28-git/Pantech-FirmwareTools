import struct
import os
import sys
from io import BytesIO
import SkyLZ
import LZB

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
		if size != 0:
			if data[0:3] == b"FWS" or data[0:3] == b"CWS" or data[0:3] == b"ZWS":
				ext = "swf"
			elif struct.unpack(">H", data[0:2])[0] & 0xFFFE == 0xFFF8:
				ext = "aac"
			elif struct.unpack(">H", data[0:2])[0] & 0xFFF0 == 0xFFF0 or data[0:3] == b"ID3":
				ext = "mp3"
			elif data[0:4] == b"MMMD":
				ext = "mmf"
			elif struct.unpack(">L", data[0:4])[0] == 0xFFD8FFE0:
				ext = "jpg"
			elif data[0:2] == b"BM":
				ext = "bmp"
			elif data[0:4] == b"\x89PNG":
				ext = "png"
			elif data[0:4] == b"RIFF" and data[8:15] == b"WAVEfmt":
				ext = "wav"
			elif data[20:28] == b"ftyp3gp4":
				data = data[16:]
				ext = "3gp"
			elif data[4:12] == b"ftypodcf":
				ext = "dcf"
			elif data[0:3] == b"KJJ":
				ext = "kjj"
			elif size >= 8 and struct.unpack("<H", data[0:2])[0] == 4: #assume its SKY LZ
				try:
					data = SkyLZ.decodeLZ(data)  
					ext = "bin"
				except Exception as e:
					ext = "bin"
			elif size >= 8 and struct.unpack("<H", data[4:6])[0] <= 16 and struct.unpack("<H", data[6:8])[0] <= 16: #assume its LZB
				try:
					data = LZB.DecompressLZB(data)  
					ext = "bin"
				except Exception as e:
					ext = "bin"
			else:
				ext = "bin"
			open(f"{out_path}/{item_no:05d}.{ext}", "wb").write(data)
		itm += 1
		