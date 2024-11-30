import struct
import os
import sys
import csv

blk_size = 512
m = 0

def get_subcont_size(fd):
	szo = 0
	poff = fd.tell()
	assert(fd.read(8) == b'\xd0\x07\x00\x00\x14\x00\x00\x00')
	items, dict_items, comp_items = struct.unpack('<LLL', fd.read(12))
	for _ in range(items):
		offs, size, size_dec = struct.unpack('<LLL', fd.read(12))
	szo = (offs*blk_size)+size
	if (size%blk_size):
		szo += (blk_size-(size%blk_size))
	fd.seek(poff)
	return szo
		

if len(sys.argv) < 2:
	print(f"Not enough arguments! usage: {sys.argv[0]} file", file=sys.stderr)
	sys.exit(1)

csv_file = open(f"{sys.argv[1]}_EXT/resource_offsets.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Item", "Offset", "Data[12:16]", "Data[16:20]"]) 

sz = os.path.getsize(sys.argv[1])
fd = open(sys.argv[1], "rb")
if not os.path.exists(f"{sys.argv[1]}_EXT"):
	os.makedirs(f"{sys.argv[1]}_EXT", exist_ok=True)

while fd.tell() < sz:
	if fd.read(4)!= b'\xd0\x07\x00\x00':
		# Seek to next 512 byte portion
		m+=1
		fd.seek(m*512)
		print(f"Did not find resource container magic, seeking to {m*512}", end="\r")
		continue
	
	print(end="\n")
	print(f"Found container at {m*512}")
	assert(fd.read(4) == b'\x18\x00\x00\x00')

	unk1, unk2, unk3, items = struct.unpack('<LLLL', fd.read(16))			   
	for i in range(items):
		offset = (struct.unpack('<L', fd.read(4))[0]+m)*512
		p_off = fd.tell()
		print(f"Item {i+1}: {offset}")
		fd.seek(offset)
		c_data = fd.read(get_subcont_size(fd))
		open(f"{sys.argv[1]}_EXT/{i+1}_{hex(offset)}.bin", "wb").write(c_data)
		data_12_16 = struct.unpack('<L', c_data[12:16])[0]
		data_16_20 = struct.unpack('<L', c_data[16:20])[0]
		csv_writer.writerow([
			i+1,
			offset,
			data_12_16,
			data_16_20
        ])
		fd.seek(p_off)
	# Break after processing one valid section
	break
else:
	print("No valid container found")
	
csv_file.close()