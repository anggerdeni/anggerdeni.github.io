---
layout: post
title:  "[RE] uwu - Arkavidia 6"
date:   2020-01-06 18:59:00
categories: ctf arkavidia
---
## Analisa
Diberikan sebuah binary file ELF 64 bit.

![](/assets/CTF/2020/Arkavidia%206/Reverse%20Engineering/uwu/ss/ss1.png)  


Program ini meminta 3 buah input.  
![](/assets/CTF/2020/Arkavidia%206/Reverse%20Engineering/uwu/ss/ss2.png)  

Langsung coba disassemble dengan menggunakan `gdb`. Karena file yang diberikan merupakan stripped binary, kita perlu mencari dulu dimana fungsi main.

Cari dulu dimana entry point program
```
gdb-peda$ info file
Symbols from "<redacted>".
Local exec file:
    `<redacted>', file type elf64-x86-64.
    Entry point: 0x1090
<snip>
```

Karena kita tahu alamat entry point adalah `0x1090`, coba saja kita decompile beberapa instruksi pada alamat tersebut.

```
gdb-peda$ pdisass 0x1090,0x10bb
Dump of assembler code from 0x1090 to 0x10bb::  Dump of assembler code from 0x1090 to 0x10bb:
   0x0000000000001090:  xor    ebp,ebp
   0x0000000000001092:  mov    r9,rdx
   0x0000000000001095:  pop    rsi
   0x0000000000001096:  mov    rdx,rsp
   0x0000000000001099:  and    rsp,0xfffffffffffffff0
   0x000000000000109d:  push   rax
   0x000000000000109e:  push   rsp
   0x000000000000109f:  lea    r8,[rip+0x4fa]        # 0x15a0
   0x00000000000010a6:  lea    rcx,[rip+0x493]        # 0x1540
   0x00000000000010ad:  lea    rdi,[rip+0x1d5]        # 0x1289
   0x00000000000010b4:  call   QWORD PTR [rip+0x2f26]        # 0x3fe0
```

Terlihat `0x1289` dimasukkan dalam register rdi sebelum perintah `call` dijalankan. Berarti ini adalah fungsi main dari program.

Coba kita disassemble beberapa instruksi dari `0x1289`
```
gdb-peda$ pdisass 0x1289,0x1537
Dump of assembler code from 0x1289 to 0x1537::  Dump of assembler code from 0x1289 to 0x1537:
   0x0000000000001289:  push   rbp
   0x000000000000128a:  mov    rbp,rsp
   0x000000000000128d:  sub    rsp,0x1d0
   0x0000000000001294:  mov    DWORD PTR [rbp-0x1c4],edi
   0x000000000000129a:  mov    QWORD PTR [rbp-0x1d0],rsi
   0x00000000000012a1:  mov    rax,QWORD PTR fs:0x28
   0x00000000000012aa:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000012ae:  xor    eax,eax
   0x00000000000012b0:  mov    DWORD PTR [rbp-0x1b7],0x212b3201
   0x00000000000012ba:  mov    WORD PTR [rbp-0x1b3],0x7636
   0x00000000000012c3:  mov    BYTE PTR [rbp-0x1b1],0x3b
   0x00000000000012ca:  mov    QWORD PTR [rbp-0x198],0x7
   0x00000000000012d5:  movabs rax,0x999a54857f759795
   0x00000000000012df:  mov    QWORD PTR [rbp-0x166],rax
   0x00000000000012e6:  mov    WORD PTR [rbp-0x15e],0x637f
   0x00000000000012ef:  mov    BYTE PTR [rbp-0x15c],0x92
   0x00000000000012f6:  mov    QWORD PTR [rbp-0x190],0xb
   0x0000000000001301:  movabs rax,0x452f033d2f3b3304
   0x000000000000130b:  mov    QWORD PTR [rbp-0x15b],rax
   0x0000000000001312:  mov    WORD PTR [rbp-0x153],0x2547
   0x000000000000131b:  mov    BYTE PTR [rbp-0x151],0x4d
   0x0000000000001322:  mov    QWORD PTR [rbp-0x188],0xb
   0x000000000000132d:  mov    DWORD PTR [rbp-0x1bc],0x1
```

Di atas terlihat terjadi inisialisasi beberapa 'variable' di stack. 
```
   0x0000000000001337:  lea    rcx,[rbp-0x70]
   0x000000000000133b:  lea    rdx,[rbp-0xe0]
   0x0000000000001342:  lea    rax,[rbp-0x150]
   0x0000000000001349:  mov    rsi,rax
   0x000000000000134c:  lea    rdi,[rip+0xcb1]        # 0x2004
   0x0000000000001353:  mov    eax,0x0
   0x0000000000001358:  call   0x1060 <__isoc99_scanf@plt>
   0x000000000000135d:  lea    rax,[rbp-0x150]
   0x0000000000001364:  mov    rdi,rax
   0x0000000000001367:  call   0x1175
```

Kemudian input kita dibagi menjadi tiga bagian, masing-masing disimpan pada \[rbp-0x70\] (input ketiga), \[rbp-0xe0\] (input kedua), \[rbp-0x150\] (input pertama).  

```
 0x000000000000134c:    lea    rdi,[rip+0xcb1]        # 0x2004
```

Setelah didebug, `0x2004` berisi '%s %s %s', dari sini kita konfirmasi bahwa input kita disimpan pada 3 tempat berbeda.

```
   0x000000000000135d:  lea    rax,[rbp-0x150]
   0x0000000000001364:  mov    rdi,rax
   0x0000000000001367:  call   0x1175
   0x000000000000136c:  mov    QWORD PTR [rbp-0x180],rax
   0x0000000000001373:  lea    rax,[rbp-0xe0]
   0x000000000000137a:  mov    rdi,rax
   0x000000000000137d:  call   0x11d1
   0x0000000000001382:  mov    QWORD PTR [rbp-0x178],rax
   0x0000000000001389:  lea    rax,[rbp-0x70]
   0x000000000000138d:  mov    rdi,rax
   0x0000000000001390:  call   0x122d
```
Selanjutnya, input pertama dijadikan argumen untuk fungsi pada address `0x1175`, demikian pula input kedua menjadi argumen untuk fungsi pada address `0x11d1`, serta input ketiga menjadi argumen untuk fungsi pada address `0x122d`.

Kemudian dilakukan pengecekan pertama sebagai berikut.
```
   0x0000000000001395:  mov    QWORD PTR [rbp-0x170],rax
   0x000000000000139c:  mov    QWORD PTR [rbp-0x1b0],0x0
   0x00000000000013a7:  jmp    0x13fd
   0x00000000000013a9:  mov    rdx,QWORD PTR [rbp-0x180]
   0x00000000000013b0:  mov    rax,QWORD PTR [rbp-0x1b0]
   0x00000000000013b7:  add    rax,rdx
   0x00000000000013ba:  movzx  edx,BYTE PTR [rax]
   0x00000000000013bd:  lea    rcx,[rbp-0x1b7]
   0x00000000000013c4:  mov    rax,QWORD PTR [rbp-0x1b0]
   0x00000000000013cb:  add    rax,rcx
   0x00000000000013ce:  movzx  eax,BYTE PTR [rax]
   0x00000000000013d1:  cmp    dl,al
   0x00000000000013d3:  je     0x13f5
   0x00000000000013d5:  mov    DWORD PTR [rbp-0x1bc],0x0
   0x00000000000013df:  lea    rdi,[rip+0xc27]        # 0x200d
   0x00000000000013e6:  call   0x1030 <puts@plt>
   0x00000000000013eb:  mov    edi,0x0
   0x00000000000013f0:  call   0x1070 <exit@plt>
   0x00000000000013f5:  add    QWORD PTR [rbp-0x1b0],0x1
   0x00000000000013fd:  mov    rax,QWORD PTR [rbp-0x1b0]
   0x0000000000001404:  cmp    rax,QWORD PTR [rbp-0x198]
   0x000000000000140b:  jb     0x13a9
```
Dilakukan iterasi sebanyak `[rbp-0x198]` kali dengan `[rbp-0x1b0]` sebagai index untuk mengambil tiap karakter dari `[rbp-0x180]`  (hasil olahan input pertama) kita. Kemudian dibandingkan dengan apa yang ada pada address `[rbp-0x1b7]`. Hasilnya harus sama semua.

Coba lihat apa yang dilakukan terhadap input pertama kita.
```
gdb-peda$ pdisass 0x1175,0x11d1
Dump of assembler code from 0x1175 to 0x11d1::  Dump of assembler code from 0x1175 to 0x11d1:
   0x0000000000001175:  push   rbp
   0x0000000000001176:  mov    rbp,rsp
   0x0000000000001179:  sub    rsp,0x20
   0x000000000000117d:  mov    QWORD PTR [rbp-0x18],rdi
   0x0000000000001181:  mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000001189:  mov    rax,QWORD PTR [rbp-0x18]
   0x000000000000118d:  mov    rdi,rax
   0x0000000000001190:  call   0x1040 <strlen@plt>
   0x0000000000001195:  mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001199:  mov    rax,QWORD PTR [rbp-0x8]
   0x000000000000119d:  cmp    rax,QWORD PTR [rbp-0x10]
   0x00000000000011a1:  jbe    0x11ca
   0x00000000000011a3:  mov    rdx,QWORD PTR [rbp-0x18]
   0x00000000000011a7:  mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011ab:  add    rax,rdx
   0x00000000000011ae:  movzx  ecx,BYTE PTR [rax]
   0x00000000000011b1:  mov    rdx,QWORD PTR [rbp-0x18]
   0x00000000000011b5:  mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011b9:  add    rax,rdx
   0x00000000000011bc:  xor    ecx,0x40
   0x00000000000011bf:  mov    edx,ecx
   0x00000000000011c1:  mov    BYTE PTR [rax],dl
   0x00000000000011c3:  add    QWORD PTR [rbp-0x10],0x1
   0x00000000000011c8:  jmp    0x1199
   0x00000000000011ca:  nop
   0x00000000000011cb:  mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011cf:  leave  
   0x00000000000011d0:  ret 
```
Pada fungsi ini hanya dilakukan xor atas tiap input kita dengan 0x40.

Pengecekan kedua
```
   0x000000000000140d:  mov    QWORD PTR [rbp-0x1a8],0x0
   0x0000000000001418:  jmp    0x146e
   0x000000000000141a:  mov    rdx,QWORD PTR [rbp-0x178]
   0x0000000000001421:  mov    rax,QWORD PTR [rbp-0x1a8]
   0x0000000000001428:  add    rax,rdx
   0x000000000000142b:  movzx  edx,BYTE PTR [rax]
   0x000000000000142e:  lea    rcx,[rbp-0x166]
   0x0000000000001435:  mov    rax,QWORD PTR [rbp-0x1a8]
   0x000000000000143c:  add    rax,rcx
   0x000000000000143f:  movzx  eax,BYTE PTR [rax]
   0x0000000000001442:  cmp    dl,al
   0x0000000000001444:  je     0x1466
   0x0000000000001446:  mov    DWORD PTR [rbp-0x1bc],0x0
   0x0000000000001450:  lea    rdi,[rip+0xbb6]        # 0x200d
   0x0000000000001457:  call   0x1030 <puts@plt>
   0x000000000000145c:  mov    edi,0x0
   0x0000000000001461:  call   0x1070 <exit@plt>
   0x0000000000001466:  add    QWORD PTR [rbp-0x1a8],0x1
   0x000000000000146e:  mov    rax,QWORD PTR [rbp-0x1a8]
   0x0000000000001475:  cmp    rax,QWORD PTR [rbp-0x190]
   0x000000000000147c:  jb     0x141a
```
Mirip dengan pengecekan pertama, hasil olahan input kedua kita yang berada pada address `[rbp-0x178]` dibandingkan dengan `[rbp-0x166]` sebanyak `[rbp-0x190]` karakter.

Lihat apa yang dilakukan terhadap input kedua kita.
```
gdb-peda$ pdisass 0x11d1,0x122d
Dump of assembler code from 0x11d1 to 0x122d::  Dump of assembler code from 0x11d1 to 0x122d:
   0x00000000000011d1:  push   rbp
   0x00000000000011d2:  mov    rbp,rsp
   0x00000000000011d5:  sub    rsp,0x20
   0x00000000000011d9:  mov    QWORD PTR [rbp-0x18],rdi
   0x00000000000011dd:  mov    QWORD PTR [rbp-0x10],0x0
   0x00000000000011e5:  mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011e9:  mov    rdi,rax
   0x00000000000011ec:  call   0x1040 <strlen@plt>
   0x00000000000011f1:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011f5:  mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000011f9:  cmp    rax,QWORD PTR [rbp-0x10]
   0x00000000000011fd:  jbe    0x1226
   0x00000000000011ff:  mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000001203:  mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001207:  add    rax,rdx
   0x000000000000120a:  movzx  eax,BYTE PTR [rax]
   0x000000000000120d:  lea    ecx,[rax+0x20]
   0x0000000000001210:  mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000001214:  mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001218:  add    rax,rdx
   0x000000000000121b:  mov    edx,ecx
   0x000000000000121d:  mov    BYTE PTR [rax],dl
   0x000000000000121f:  add    QWORD PTR [rbp-0x10],0x1
   0x0000000000001224:  jmp    0x11f5
   0x0000000000001226:  nop
   0x0000000000001227:  mov    rax,QWORD PTR [rbp-0x18]
   0x000000000000122b:  leave  
   0x000000000000122c:  ret
```

Perhatikan pada instruksi ini
```
   0x000000000000120d:  lea    ecx,[rax+0x20]
```
tiap byte input kita ditambah dengan 0x20


Pengecekan ketiga.
```
   0x000000000000147e:  mov    QWORD PTR [rbp-0x1a0],0x0
   0x0000000000001489:  jmp    0x14df
   0x000000000000148b:  mov    rdx,QWORD PTR [rbp-0x170]
   0x0000000000001492:  mov    rax,QWORD PTR [rbp-0x1a0]
   0x0000000000001499:  add    rax,rdx
   0x000000000000149c:  movzx  edx,BYTE PTR [rax]
   0x000000000000149f:  lea    rcx,[rbp-0x15b]
   0x00000000000014a6:  mov    rax,QWORD PTR [rbp-0x1a0]
   0x00000000000014ad:  add    rax,rcx
   0x00000000000014b0:  movzx  eax,BYTE PTR [rax]
   0x00000000000014b3:  cmp    dl,al
   0x00000000000014b5:  je     0x14d7
   0x00000000000014b7:  mov    DWORD PTR [rbp-0x1bc],0x0
   0x00000000000014c1:  lea    rdi,[rip+0xb45]        # 0x200d
   0x00000000000014c8:  call   0x1030 <puts@plt>
   0x00000000000014cd:  mov    edi,0x0
   0x00000000000014d2:  call   0x1070 <exit@plt>
   0x00000000000014d7:  add    QWORD PTR [rbp-0x1a0],0x1
   0x00000000000014df:  mov    rax,QWORD PTR [rbp-0x1a0]
   0x00000000000014e6:  cmp    rax,QWORD PTR [rbp-0x188]
   0x00000000000014ed:  jb     0x148b
```
Mirip dengan pengecekan sebelumnya, hasil olahan input kedua kita yang berada pada address `[rbp-0x170]` dibandingkan dengan `[rbp-0x15b]` sebanyak `[rbp-0x188]` karakter.

Lihat fungsi yang memanipulasi input ketiga.

```
gdb-peda$ pdisass 0x122d,0x1289
Dump of assembler code from 0x122d to 0x1289::  Dump of assembler code from 0x122d to 0x1289:
   0x000000000000122d:  push   rbp
   0x000000000000122e:  mov    rbp,rsp
   0x0000000000001231:  sub    rsp,0x20
   0x0000000000001235:  mov    QWORD PTR [rbp-0x18],rdi
   0x0000000000001239:  mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000001241:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000000000001245:  mov    rdi,rax
   0x0000000000001248:  call   0x1040 <strlen@plt>
   0x000000000000124d:  mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001251:  mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001255:  cmp    rax,QWORD PTR [rbp-0x10]
   0x0000000000001259:  jbe    0x1282
   0x000000000000125b:  mov    rdx,QWORD PTR [rbp-0x18]
   0x000000000000125f:  mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001263:  add    rax,rdx
   0x0000000000001266:  movzx  eax,BYTE PTR [rax]
   0x0000000000001269:  lea    ecx,[rax-0x30]
   0x000000000000126c:  mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000001270:  mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001274:  add    rax,rdx
   0x0000000000001277:  mov    edx,ecx
   0x0000000000001279:  mov    BYTE PTR [rax],dl
   0x000000000000127b:  add    QWORD PTR [rbp-0x10],0x1
   0x0000000000001280:  jmp    0x1251
   0x0000000000001282:  nop
   0x0000000000001283:  mov    rax,QWORD PTR [rbp-0x18]
   0x0000000000001287:  leave  
   0x0000000000001288:  ret 
```
Perhatikan perintah ini
```
   0x0000000000001269:  lea    ecx,[rax-0x30]
```
Tiap karakter input kita dikurangi 0x30

## Solve
Cukup sederhana, jalankan saja debugger (gdb), sampai selesai inisialisasi variabel. 
```
b *0x555555555337
```

Input pertama
```
gdb-peda$ x/b $rbp-0x198
0x7fffffffdba8: 0x07
gdb-peda$ x/7b $rbp-0x1b7
0x7fffffffdb89: 0x01    0x32    0x2b    0x21    0x36    0x76    0x3b

```

Input kedua
```
gdb-peda$ x/b $rbp-0x190
0x7fffffffdbb0: 0x0b
gdb-peda$ x/11b $rbp-0x166
0x7fffffffdbda: 0x95    0x97    0x75    0x7f    0x85    0x54    0x9a    0x99
0x7fffffffdbe2: 0x7f    0x63    0x92
```

Input ketiga
```
gdb-peda$ x/b $rbp-0x188
0x7fffffffdbb8: 0x0b
gdb-peda$ x/11b $rbp-0x15b
0x7fffffffdbe5: 0x04    0x33    0x3b    0x2f    0x3d    0x03    0x2f    0x45
0x7fffffffdbed: 0x47    0x25    0x4d

```

```py
input1 = [0x01, 0x32, 0x2b, 0x21, 0x36, 0x76, 0x3b]
flag = ''
for i in input1:
    flag += chr(i^0x40)

input2 = [0x95, 0x97, 0x75, 0x7f, 0x85, 0x54, 0x9a, 0x99, 0x7f, 0x63, 0x92]
for i in input2:
    flag += chr(i - 0x20)

input3 = [0x04, 0x33, 0x3b, 0x2f, 0x3d, 0x03, 0x2f, 0x45, 0x47, 0x25, 0x4d]
for i in input3:
    flag += chr(i + 0x30)

print(flag)
```

## Flag
Arkav6{uwU_e4zy_Cr4ck_m3_uwU}