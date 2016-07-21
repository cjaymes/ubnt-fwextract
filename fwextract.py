#!/usr/bin/python

# Copyright 2016 Casey Jaymes

# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this.  If not, see <http://www.gnu.org/licenses/>.

import sys, binascii, struct

if len(sys.argv) <= 1:
	sys.stderr.write('!!! Usage: ', sys.argv[0], ' firmware_file\n')
	sys.exit(1)

with open(sys.argv[1], 'r', 0) as f:

	magic = f.read(4)
	crc = binascii.crc32(magic)
	if magic == 'OPEN':
		print '*** Firmware file'
	else:
		sys.stderr.write('!!! Invalid firmware file\n')
		sys.exit(1)

	fw_version = f.read(256)
	crc = binascii.crc32(fw_version, crc)
	print 'Version: ' + fw_version

	#print 'Calculated CRC: 0x' + "%08x" % (crc & 0xffffffff)
	header_crc = f.read(4)
	fw_crc = binascii.crc32(header_crc, crc)
	header_crc = binascii.b2a_hex(header_crc)
	print 'Header CRC: 0x' + header_crc
	if header_crc != "%08x" % (crc & 0xffffffff):
		sys.stderr.write('!!! Header CRC Mismatch\n')
		sys.exit(1)

	header_pad = f.read(4)	# pad
	fw_crc = binascii.crc32(header_pad, fw_crc)

	while True:
		magic = f.read(4)
		if magic == 'PART':
			crc = binascii.crc32(magic)
			fw_crc = binascii.crc32(magic, fw_crc)
			print '*** Firmware partition'

			part_name = f.read(16)
			crc = binascii.crc32(part_name, crc)
			fw_crc = binascii.crc32(part_name, fw_crc)
			print 'Name: ' + part_name

			part_pad = f.read(12)	# pad
			crc = binascii.crc32(part_pad, crc)
			fw_crc = binascii.crc32(part_pad, fw_crc)

			part_mem_addr = f.read(4)
			crc = binascii.crc32(part_mem_addr, crc)
			fw_crc = binascii.crc32(part_mem_addr, fw_crc)
			print 'Mem Address: 0x' + binascii.b2a_hex(part_mem_addr)

			part_index = f.read(4)
			crc = binascii.crc32(part_index, crc)
			fw_crc = binascii.crc32(part_index, fw_crc)
			#print 'Index (hex): ' + binascii.b2a_hex(i)
			part_index = struct.unpack('!I', part_index)[0]
			print 'Index: ' + str(part_index)

			part_base_addr = f.read(4)
			crc = binascii.crc32(part_base_addr, crc)
			fw_crc = binascii.crc32(part_base_addr, fw_crc)
			print 'Base Address: 0x' + binascii.b2a_hex(part_base_addr)

			part_entry_addr = f.read(4)
			crc = binascii.crc32(part_entry_addr, crc)
			fw_crc = binascii.crc32(part_entry_addr, fw_crc)
			print 'Entry Address: 0x' + binascii.b2a_hex(part_entry_addr)

			part_data_size = f.read(4)
			crc = binascii.crc32(part_data_size, crc)
			fw_crc = binascii.crc32(part_data_size, fw_crc)
			part_data_size = struct.unpack('!I', part_data_size)[0]
			print 'Data Size: ' + str(part_data_size)

			part_size = f.read(4)
			crc = binascii.crc32(part_size, crc)
			fw_crc = binascii.crc32(part_size, fw_crc)
			part_size = struct.unpack('!I', part_size)[0]
			print 'Part Size: ' + str(part_size)

			pfname = f.name + '.part' + str(part_index)
			print "Opening " + pfname + " to write " + str(part_size) + " byte partition"
			with open(pfname, 'w') as p:
				while part_data_size > 0:
					if part_data_size > 1024:
						#print "Writing 1024 bytes"
						buf = f.read(1024)
						crc = binascii.crc32(buf, crc)
						fw_crc = binascii.crc32(buf, fw_crc)
						p.write(buf)
						part_data_size -= 1024
					else:
						#print "Writing " + str(part_size) + " bytes"
						buf = f.read(part_data_size)
						crc = binascii.crc32(buf, crc)
						fw_crc = binascii.crc32(buf, fw_crc)
						p.write(buf)
						part_data_size = 0
			print "Writing file complete"

			#print 'Calculated CRC: 0x' + "%08x" % (crc & 0xffffffff)
			part_crc = f.read(4)
			fw_crc = binascii.crc32(part_crc, fw_crc)
			part_crc = binascii.b2a_hex(part_crc)
			print 'Part CRC: 0x' + part_crc
			if part_crc != "%08x" % (crc & 0xffffffff):
				sys.stderr.write('!!! Part ' + str(part_index) + ' CRC Mismatch\n')
				sys.exit(1)

			part_pad = f.read(4)	# pad
			fw_crc = binascii.crc32(part_pad, fw_crc)

		elif magic == 'END.':
			print '*** Firmware signature'
			sign_crc = binascii.b2a_hex(f.read(4))
			print 'Signature CRC: 0x' + sign_crc
			#print 'Calculated CRC: 0x' + "%08x" % (fw_crc & 0xffffffff)
			if sign_crc != "%08x" % (fw_crc & 0xffffffff):
				sys.stderr.write('!!! Signature CRC Mismatch\n')
				sys.exit(1)

			f.read(4)	# pad

			if f.read(1) != '':
				sys.stderr.write("!!! Finished parsing file, but data remains\n")
			break
		else:
			sys.stderr.write('!!! Invalid magic: ' + binascii.b2a_hex(magic) + '\n')
			break
