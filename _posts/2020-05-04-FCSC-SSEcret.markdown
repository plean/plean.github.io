---
layout: post
title:  "SSEcret"
date:   2020-05-04 08:18:37 +0200
categories: writeup
---

# FCSC

## Reverse Engineering

### SSEcret

Le binaire est un ELF 64 bits et prend un secret en paramêtre
```bash
plean@ubuntu:~/ctf/fcsc-2020/reverse/SSEcreT$ file ssecret.bin
ssecret.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=bc0fff26311919cb6ebc99a23c993763db59299e, stripped
plean@ubuntu:~/ctf/fcsc-2020/reverse/SSEcreT$ ./ssecret.bin
Usage: ./ssecret.bin <secret>
```

----------

#### Énumération:

Nous lançons DIA et analysons le programme.

```c
__int64 __fastcall main(int argc, char **argv, char **envp)
{
  void *v4; // rax@4
  __int64 v5; // [sp+0h] [bp-18h]@4
  __int64 v6; // [sp+8h] [bp-10h]@1

  v6 = *MK_FP(__FS__, 40LL);
  if ( argc == 2 )
  {
    v4 = sub_400860(argv[1], strlen(argv[1]), &v5);
    sub_601050(v4, v5);
  }
  else
  {
    __printf_chk(1LL, "Usage: %s <secret>\n", *argv);
  }
  return 0LL;
}
```

Jusqu'à là rien de bien complexe nous passons à la fonction `sub_400860`.
Celle-ci un peu plus longue est rapidement reconnue, en effet elle effectue un `b64decode` sur la chaine passé en paramêtre, en revoie le résultat et stock le nombre de bytes écrit dans `v5`.

Le seconde fonction quand a elle est bien plus complexe.
Elle peut être découpé en deux parties:

La première partie charge deux valeurs, une dans `rax` et une dans `rbx`,  puis les xor avec les `0x10` premiers bytes de l'entrée utilisateur, une fois base64 decodé, les highbits pour `rbx` et les lowbits pour `rax`.
Puis l'instruction `popcnt` est utilisé sur les deux registres, cette operation va compter le nombre de bits non zéros et ce résultat sera `& 1`.
Au final si les deux résultats sont égaux, c'est à dire que les nombres de bits sont tous les deux soit pair, soit impair, on jump au block suivant, sinon le nième bit de `xmm3` est set à `1`. 
```asm
loc_601373:
 psrlq   xmm2, 1
 mov     rax, 64CE525FF893C2Ch
 mov     rbx, 6CE07930082C6E66h
 movq    xmm1, rax
 pinsrq  xmm1, rbx, 1
 pand    xmm1, xmm0
 vmovq   rax, xmm1
 vpextrq rbx, xmm1, 1
 popcnt  rax, rax
 and     rax, 1
 popcnt  rbx, rbx
 and     rbx, 1
 xor     rax, rbx
 test    rax, rax
 jz      short loc_6013C5
 pxor    xmm3, xmm2
loc_6013C5:
```
Ce block se répète un certain nombre de fois avec des valeurs différentes pour `rax` et `rbx` à chaques fois, jusqu'à ce que tout les bits de `xmm3` soient set ou non.

Une fois cela fait deux valeurs sont à nouveaux chargé dans `rax` et `rbx` et sont comparés à `xmm3`, si les valeurs sont différentes on `exit` le programme.

Il nous faut donc trouver `16` bytes pour lesquels le check final sera juste.

Pour cela on écrit un petit algorithme qui calculera l'input pour nous.

```python
blank = []
final_list = list(map(int, bin(final)[2:].zfill(128))) # final is the final number we want to reach
arr = [
]
for _ in range(128):
    arr.append([])

for nb1, nb2 in nbs: # ns is all the couples for rax and rbx
    res = (popcount(nb1 & 0x0) & 1) ^ (popcount(nb2 & 0x0) & 1)
    blank.append(res)
    for i in range(128):
        tmp = 1 << i
        arr[i].append((popcount(nb1 & tmp) & 1) ^
                      (popcount(nb2 & (tmp >> 64)) & 1) ^ res)
    pass

usables = [ [arr[i], 1 << i] for i in range(128) ]
transform = [ blank, 0x0 ]


for i in range(128):
    for item in usables:
        if transform[0][i] ^ item[0][i] == final_list[i]:
            for j in range(128):
                transform[0][j] ^= item[0][j]
            transform[1] ^= item[1]
            break
    else:
        if transform[0][i] != final_list[i]:
            print("[-] no solution")
            exit()
        continue
    new_usables = []
    for item in usables:
        if item[0][i]:
            for item2 in usables:
                if item2[0][i]:
                    item_tmp = [ [], item[1] ^ item2[1] ]
                    for j in range(128):
                        item_tmp[0].append(item[0][j] ^ item2[0][j])
                    new_usables.append(item_tmp)
                    break
        else:
            new_usables.append(item)
    usables = new_usables

assert cmp(final_list, transform[0])
print("[+] input:", long_to_bytes(transform[1])[::-1])
```

S'ensuit la génération d'une clé aes puis le déchiffrage du block de code suivant avec.
Une fois le block déchiffré, on jump dessus et on continue.

Les blocks suivant sont à chaques fois similaire au précédents, si ce n'est les valeurs pour `rax` et `rbx` et le check final, jusqu'au block affichant le flag.

Afin d'automatiser tout ceci, nous utilison un script gdb pour récupérer les valeurs qui seront notre `final` et nos `nbs`

```python
gdb.execute("tb *0x400588")
gdb.execute('r "%s"' % b64encode(inpt).decode())

for i in range(itr):
    addr = start + 0x2c00 * i
    gdb.execute("tb *%x" % addr)
    gdb.execute("c")
    gdb.execute("b *%x" % (start + 0x2bee + 0x2c00 * i))
    gdb.execute("c")
    gdb.execute("c 0x2bf")

addr = start + 0x2c00 * itr

gdb.execute("tb *%x" % addr)
gdb.execute("c")

nbs = []
for i in range(64):
    nb1 = gdb.execute("x/i %x" % (addr + 0x46 + i * (0xe8 - 0x96)), to_string=True)
    nb2 = gdb.execute("x/i %x" % (addr + 0x50 + i * (0xe8 - 0x96)), to_string=True)
    nbs.append((int(nb1[nb1.index(',') + 1:-1], 16), int(nb2[nb2.index(',') + 1:-1], 16)))
for i in range(64):
    nb1 = gdb.execute("x/i %x" % (addr + 0x14e3 + i * (0xe8 - 0x96)), to_string=True)
    nb2 = gdb.execute("x/i %x" % (addr + 0x14ed + i * (0xe8 - 0x96)), to_string=True)
    nbs.append((int(nb1[nb1.index(',') + 1:-1], 16), int(nb2[nb2.index(',') + 1:-1], 16)))


rax = gdb.execute("x/i %x" % (addr + 0x2963), to_string=True)
rbx = gdb.execute("x/i %x" % (addr + 0x296D), to_string=True)

final = (int(rbx[rbx.index(',') + 1:-1], 16) << 64) | int(rax[rax.index(',') + 1:-1], 16)
```

Nous mettons les deux parties en commun et lançons le script et resolvons le challenge.
