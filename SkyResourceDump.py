import struct
import os
import sys
import SkyCFLib
from io import BytesIO

blk_size = 512

if len(sys.argv) < 2:
	print(f"Not enough arguments! usage: {sys.argv[0]} file", file=sys.stderr)
	sys.exit(1)

sz = os.path.getsize(sys.argv[1])
fd = open(sys.argv[1], "rb")
if not os.path.exists(f"{sys.argv[1]}_EXT"):
	os.makedirs(f"{sys.argv[1]}_EXT", exist_ok=True)

assert(fd.read(8) == b'\xd0\x07\x00\x00\x14\x00\x00\x00')
items, type, unknown = struct.unpack("<LLL", fd.read(12))
for idx in range(items):
	blk_off, size, cmp_size = struct.unpack("<LLL", fd.read(12))
	off_t = fd.tell()
	fd.seek(blk_off*blk_size)
	data = fd.read(size)

	if data[0:4] == b"MMMD":
		print(f"Sound found at {idx}")
		if not os.path.exists(f"{sys.argv[1]}_EXT/Sound"):
			os.makedirs(f"{sys.argv[1]}_EXT/Sound", exist_ok=True)
		open(f"{sys.argv[1]}_EXT/Sound/{idx}.mmf", "wb").write(data)
	elif data[0:2] == b"AF" and size >= 10:
		print(f"Image found at {idx}")
		if not os.path.exists(f"{sys.argv[1]}_EXT/Image"):
			os.makedirs(f"{sys.argv[1]}_EXT/Image", exist_ok=True)
		dimg = SkyCFLib.AF(data)
		for c, im in enumerate(dimg):
			if not os.path.exists(f"{sys.argv[1]}_EXT/Image/{idx}"):
				os.makedirs(f"{sys.argv[1]}_EXT/Image/{idx}", exist_ok=True)
			im.save(f"{sys.argv[1]}_EXT/Image/{idx}/{c}.png")
	elif data[0:2] == b"CF" and size >= 14:
		print(f"Image found at {idx}")
		if not os.path.exists(f"{sys.argv[1]}_EXT/Image"):
			os.makedirs(f"{sys.argv[1]}_EXT/Image", exist_ok=True)
		dimg = SkyCFLib.decodeFrame2(data)
		dimg.save(f"{sys.argv[1]}_EXT/Image/{idx}.png")
	else:
		open(f"{sys.argv[1]}_EXT/{idx}_{hex(blk_off*blk_size)}.bin", "wb").write(data)

	fd.seek(off_t)