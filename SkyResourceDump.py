import struct
import os
import sys
import SkyCFLib
from io import BytesIO
import csv

blk_size = 512

if len(sys.argv) < 2:
	print(f"Not enough arguments! usage: {sys.argv[0]} file", file=sys.stderr)
	sys.exit(1)

sz = os.path.getsize(sys.argv[1])
fd = open(sys.argv[1], "rb")

assert(fd.read(8) == b'\xd0\x07\x00\x00\x14\x00\x00\x00')
items, group, type = struct.unpack("<LLL", fd.read(12))

csv_is_open = False
folder_path = os.path.split(os.path.abspath(sys.argv[1]))[0]
out_path = f"{folder_path}/Out/{group}"

if not os.path.exists(out_path):
	os.makedirs(out_path, exist_ok=True)
	
for idx in range(items):
	#IM-U160K: 0 - string, 1 - still image, 2 - animation, 3 - sound,
	if type == 0:
		if csv_is_open == False:
			csv_file = open(f"{out_path}/strings.csv", "w", newline="", encoding="utf-16")
			csv_writer = csv.writer(csv_file, delimiter='\t')
			csv_writer.writerow(["Korean", "English"]) 
			csv_is_open = True
		blk_off, offset, korean_size, english_size = struct.unpack("<LLLL", fd.read(16))
		off_t = fd.tell()
		fd.seek(blk_off*blk_size+offset)
		kr_str = fd.read(korean_size).decode('euc-kr')
		en_str = fd.read(english_size).decode('euc-kr')
		csv_writer.writerow([kr_str, en_str])
	else:
		blk_off, size, cmp_size = struct.unpack("<LLL", fd.read(12))
		off_t = fd.tell()
		print(hex(blk_off*blk_size), size, cmp_size)
		fd.seek(blk_off*blk_size)
		data = fd.read(size)
		if type == 1 or type == 2:
			if not os.path.exists(f"{out_path}/Image"):
				os.makedirs(f"{out_path}/Image", exist_ok=True)
			if data[0:2] == b"AF" and size >= 10:
				dimg = SkyCFLib.AF(data)
				for c, im in enumerate(dimg):
					if not os.path.exists(f"{out_path}/Image/{idx}"):
						os.makedirs(f"{out_path}/Image/{idx}", exist_ok=True)
					im.save(f"{out_path}/Image/{idx}/{c}.png")
			elif data[0:2] == b"CF" and size >= 14:
				dimg = SkyCFLib.decodeFrame2(data)
				dimg.save(f"{out_path}/Image/{idx}.png")
		elif type == 3:
			if not os.path.exists(f"{out_path}/Sound"):
				os.makedirs(f"{out_path}/Sound", exist_ok=True)
			if data[0:4] == b"MMMD":
				open(f"{out_path}/Sound/{idx}.mmf", "wb").write(data)
			else:
				open(f"{out_path}/Sound/{idx}.aac", "wb").write(data)
		elif type == 4:
			if not os.path.exists(f"{out_path}/Font"):
				os.makedirs(f"{out_path}/Font", exist_ok=True)
			if data[0:2] == b"FT" and size >= 16:
				open(f"{out_path}/Font/{idx}.fnt", "wb").write(data)
		else:
			open(f"{out_path}/{idx}_{hex(blk_off*blk_size)}.bin", "wb").write(data)

	fd.seek(off_t)