---
layout: post
title:  "[Crypto] RockPaperScissors - nullcon HackIM 2020"
date:   2020-02-11 00:00:00
categories: ctf nullcon
---
## Analisa
Diberikan sebuah file `rps.py`  
```py
#!/usr/bin/env python3
from Crypto import Random
from Crypto.Random import random
from Crypto.Util.number import *
from secret import flag

sbox = [221, 229, 120, 8, 119, 143, 33, 79, 22, 93, 239, 118, 130, 12, 63, 207, 90, 240, 199, 20, 181, 4, 139, 98, 78, 32, 94, 108, 100, 223, 1, 173, 220, 238, 217, 152, 62, 121, 117, 132, 2, 55, 125, 6, 34, 201, 254, 0, 228, 48, 250, 193, 147, 248, 89, 127, 174, 210, 57, 38, 216, 225, 43, 15, 142, 66, 70, 177, 237, 169, 67, 192, 30, 236, 131, 158, 136, 159, 9, 148, 103, 179, 141, 11, 46, 234, 36, 18, 191, 52, 231, 23, 88, 145, 101, 17, 74, 44, 122, 75, 235, 175, 54, 40, 27, 109, 73, 202, 129, 215, 83, 186, 7, 163, 29, 115, 243, 13, 105, 184, 68, 124, 189, 39, 140, 138, 165, 219, 161, 150, 59, 233, 208, 226, 176, 144, 113, 146, 19, 224, 111, 126, 222, 178, 47, 252, 99, 87, 134, 249, 69, 198, 164, 203, 194, 170, 26, 137, 204, 157, 180, 168, 162, 56, 81, 253, 213, 45, 21, 58, 24, 171, 37, 82, 53, 50, 84, 196, 232, 242, 244, 64, 80, 10, 114, 212, 187, 205, 28, 51, 182, 16, 107, 245, 211, 85, 92, 195, 5, 197, 200, 31, 183, 61, 123, 86, 167, 154, 41, 151, 35, 247, 246, 153, 95, 206, 149, 76, 112, 71, 230, 106, 188, 172, 241, 72, 156, 49, 14, 214, 155, 110, 102, 116, 128, 160, 135, 104, 77, 91, 190, 60, 42, 185, 96, 97, 251, 218, 133, 209, 65, 227, 3, 166, 255, 25]
p = [5, 9, 1, 8, 3, 11, 0, 12, 7, 4, 14, 13, 10, 15, 6, 2]
round = 16


def pad(data, size = 16):
    pad_byte = (size - len(data) % size) % size
    data = data + bytearray([pad_byte]) * pad_byte
    return data

def repeated_xor(p, k):
    return bytearray([p[i] ^ k[i % len(k)] for i in range(len(p))])

def bytes_to_int(xbytes):
    return bytes_to_long(xbytes)

def int_to_bytes(x):
    return long_to_bytes(x, 16)

def group(input, size = 16):
    return [input[i * size: (i + 1) * size] for i in range(len(input) // size)]

def hash(data):
    state = bytearray([208, 151, 71, 15, 101, 206, 50, 225, 223, 14, 14, 106, 22, 40, 20, 2])
    data = pad(data, 16)
    data = group(data)
    for roundkey in data:
        for _ in range(round):
            state = repeated_xor(state, roundkey)
            for i in range(len(state)):
                state[i] = sbox[state[i]]
            temp = bytearray(16)
            for i in range(len(state)):
                temp[p[i]] = state[i]
            state = temp
    return hex(bytes_to_int(state))[2:]

def gen_commitments():
    secret = bytearray(Random.get_random_bytes(16))
    rc = hash(secret + b"r")
    pc = hash(secret + b"p")
    sc = hash(secret + b"s")
    secret = hex(bytes_to_int(secret))[2:]
    rps = [("r", rc), ("p", pc), ("s", sc)]
    random.shuffle(rps)
    return secret, rps

def check_win(a, b):
    if a == "r":
        if b == "p":
            return True
        else:
            return False
    elif a == "s":
        if b == "r":
            return True
        else:
            return False
    elif a == "p":
        if b == "s":
            return True
        else:
            return False
    return False

def main():
    print("Beat me in Rock Paper Scissors 20 consecutive times to get the flag")
    for i in range(20):
        secret, rps = gen_commitments()
        move = rps[0][0]
        print("Here are the possible commitments, the first one is my move:", " ".join(map(lambda s: s[1], rps)))
        inp = input("Your move:")
        res = check_win(move, inp)
        print("My move was:", move, "Secret was:", secret)
        if not res:
            print("You lose!")
            exit(0)

    print("You win")
    print("Your reward is", flag)
    exit(0)

if __name__ == '__main__':
    main()
```

Setelah dilihat-lihat, secara sederhananya program ini melakukan hal sebagai berikut:  
1. Generate secret berupa 16 random bytes
2. Untuk masing-masing rock ('r'), paper ('p'), dan scissors ('s'), generate hash untuk masing-masing secret+karakter dengan state awal yang sama.
3. Hasil hash dishuffle, server mengambil pilihan pertama dari hasil shuffle tersebut, berarti kita harus menebak yang mana yang merupakan lawan pilihan yang benar agar bisa menang
4. Kita harus menang sebanyak 20 kali agar bisa mendapatkan flag

Kita lihat di sini input untuk fungsi hash dipadding sebanyak 16 bytes. Karena secret sendiri sudah 16 bytes, setelah ditambah 1 byte 'r'/'p'/'s' maka input untuk fungsi hash adalah sepanjang 17 bytes. Data ini kemudian dipadding menjadi 32 bytes dengan menambahkan 15 bytes '\x0f' kemudian dilakukan grouping masing-masing 16 bytes. Sehingga kita akan memiliki 2 group untuk masing-masing input dengan group pertama adalah secret sementara group kedua 'r'/'p'/'s' + '\x0f'*15. Group-group ini yang akan digunakan menjadi roundKeys untuk tahap berikutnya.

```py
def hash(data):
    state = bytearray([208, 151, 71, 15, 101, 206, 50, 225, 223, 14, 14, 106, 22, 40, 20, 2])
    data = pad(data, 16)
    data = group(data)
    for roundkey in data:
        for _ in range(round):
            state = repeated_xor(state, roundkey)
            for i in range(len(state)):
                state[i] = sbox[state[i]]
            temp = bytearray(16)
            for i in range(len(state)):
                temp[p[i]] = state[i]
            state = temp
    return hex(bytes_to_int(state))[2:]
```

Disinilah letak kelemahan hash function ini. Karena kita tahu dari awal bahwa untuk ketiga input, group pertama selalu berisi data yang sama yaitu secret sepanjang 16 bytes, maka untuk tiap input itu setelah roundKey pertama selesai diproses (16 round) hasil dari state nya akan sama. Baru setelah itu untuk roundKey kedua akan diproses selama 16 round juga.

Maka kita hanya perlu mereverse proses hashing dari ketiga hash yang diberikan (hash dari secret+move yang kemudian dishuffle) dengan mencoba permutasi kemungkinan dari ketiga hash tersebut.

Untuk permutasi yang benar, maka setelah proses reverse hasil state ketiga hash itu haruslah sama.

Misalkan kita diberikan secret berupa 'SSSSSSSSSSSSSSSS' serta hash x,y,z yang kita tidak tahu urutan move dari hash tersebut (bisa saja rps/rsp/prs/srp, dsb) dan setelah proses hashing dengan roundKey pertama untuk masing-masing input diperoleh state 'ABCDEFGHIJKLMNOP'.

Maka kita hanya perlu melakukan reverse proses hash sebanyak 16 round untuk masing-masing permutasi yang memungkinkan (rps/rsp/prs/psr, dsb) dan mencari yang hasil dari proses reverse tersebut sama untuk ketiga input.

Untuk proses reverse hashing nya, digunakan fungsi sebagai berikut:

```py
def balikin(s,inp):
    orig = bytearray(16)
    s = int_to_bytes(int(s,16))
    prev_state = s
    for x in range(16):
        for i in range(len(p)):
            orig[i] = prev_state[p[i]]
        for i in range(len(orig)):
            orig[i] = sbox.index(orig[i])
        prev_state = repeated_xor(orig, inp+b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f')
    return prev_state
```
Fungsi ini mengambil 2 argumen yaitu s (state akhir) serta inp (tebakan input kita, bisa 'r'/'s'/'p').


## Solve
```py
#!/usr/bin/env python3
from Crypto import Random
from Crypto.Random import random
from Crypto.Util.number import *
from itertools import permutations

sbox = [221, 229, 120, 8, 119, 143, 33, 79, 22, 93, 239, 118, 130, 12, 63, 207, 90, 240, 199, 20, 181, 4, 139, 98, 78, 32, 94, 108, 100, 223, 1, 173, 220, 238, 217, 152, 62, 121, 117, 132, 2, 55, 125, 6, 34, 201, 254, 0, 228, 48, 250, 193, 147, 248, 89, 127, 174, 210, 57, 38, 216, 225, 43, 15, 142, 66, 70, 177, 237, 169, 67, 192, 30, 236, 131, 158, 136, 159, 9, 148, 103, 179, 141, 11, 46, 234, 36, 18, 191, 52, 231, 23, 88, 145, 101, 17, 74, 44, 122, 75, 235, 175, 54, 40, 27, 109, 73, 202, 129, 215, 83, 186, 7, 163, 29, 115, 243, 13, 105, 184, 68, 124, 189, 39, 140, 138, 165, 219, 161, 150, 59, 233, 208, 226, 176, 144, 113, 146, 19, 224, 111, 126, 222, 178, 47, 252, 99, 87, 134, 249, 69, 198, 164, 203, 194, 170, 26, 137, 204, 157, 180, 168, 162, 56, 81, 253, 213, 45, 21, 58, 24, 171, 37, 82, 53, 50, 84, 196, 232, 242, 244, 64, 80, 10, 114, 212, 187, 205, 28, 51, 182, 16, 107, 245, 211, 85, 92, 195, 5, 197, 200, 31, 183, 61, 123, 86, 167, 154, 41, 151, 35, 247, 246, 153, 95, 206, 149, 76, 112, 71, 230, 106, 188, 172, 241, 72, 156, 49, 14, 214, 155, 110, 102, 116, 128, 160, 135, 104, 77, 91, 190, 60, 42, 185, 96, 97, 251, 218, 133, 209, 65, 227, 3, 166, 255, 25]
p = [5, 9, 1, 8, 3, 11, 0, 12, 7, 4, 14, 13, 10, 15, 6, 2]
round = 16


def pad(data, size = 16):
    pad_byte = (size - len(data) % size) % size
    data = data + bytearray([pad_byte]) * pad_byte
    return data

def repeated_xor(p, k):
    return bytearray([p[i] ^ k[i % len(k)] for i in range(len(p))])

def bytes_to_int(xbytes):
    return bytes_to_long(xbytes)

def int_to_bytes(x):
    return long_to_bytes(x, 16)

def balikin(s,inp):
    orig = bytearray(16)
    s = int_to_bytes(int(s,16))
    prev_state = s
    for x in range(16):
        for i in range(len(p)):
            orig[i] = prev_state[p[i]]
        for i in range(len(orig)):
            orig[i] = sbox.index(orig[i])
        prev_state = repeated_xor(orig, inp+b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f')
    return prev_state

h1,h2,h3 = '3eacb08f61e6bd5ed11a7492f2202172 7d0f1f13926a9118476eabfbf07dddd6 7b7033f7e5bc41d1ccfb1883e7c850e2'.split(' ') # diperoleh dari server, manual ganti-ganti sebanyak 20 kali

perm_list = list(permutations([b'r',b'p',b's']))
for i in perm_list:
    r1, r2, r3 = balikin(h1,i[0]), balikin(h2,i[1]), balikin(h3,i[2])
    if r1==r2==r3:
        print(i)
        break
```
Untuk script ini, masih menggunakan cara manual yaitu mengganti-ganti hash yang diberikan langsung di source code karena saya malas dan hanya memerlukan 20 iterasi. Hasil dari script ini adalah urutan yang benar dari ketiga hash yang diberikan. Sebagai contoh untuk input di atas hasilnya:  
```
> python3 solve.py
(b'r', b's', b'p')
```

Karena kita tahu server memilih 'r' maka kita harus memilih 'p' agar bisa menang. Begini seterusnya sampai 20 kali.

## Flag
hackim20{b4d_pr1mitiv3_beats_all!1!_7f65}