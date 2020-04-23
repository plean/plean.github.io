---
layout: post
title:  "Efficiency"
date:   2019-10-07 17:45:03 +0100
categories: writeup
---

# Sigsegv2 quals

## Reverse engineering

### Efficiency

Writeup par plean

Ce challenge était le seul challenge de reverse des qualifications de la sigsegv2, événement sur la sécurité informatique organisé par RTFM.

Le binaire en lui-même est un ELF 64bits et demande un mot de passe sur l'entrée standard.
```bash
$ file efficiency_fixed
efficiency: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=f693cdf059187489ca90aa7581eb588cc3cc5163, for GNU/Linux 3.2.0, stripped
$ ./efficiency_fixed
Please enter the password:
aaaaaaa
# ...nothing...
```

----------


Maintenant que nous savons tous ça plongeons-nous au coeur du problème, lançons IDA et analysons le code.

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 buf; // [sp+0h] [bp-20h]@1
  __int64 v4; // [sp+8h] [bp-18h]@1
  int v5; // [sp+10h] [bp-10h]@1
  char v6; // [sp+14h] [bp-Ch]@1

  buf = 0LL;
  v4 = 0LL;
  v5 = 0;
  v6 = 0;
  puts("Please enter the password: ");
  read(0, &buf, 0x14uLL);
  sub_138B(&buf, &buf);
}
```

Okay donc les 20 premiers caractères sont lu et chargé dans `buf` puis envoyé à `sub_138B`.
On regarde ce que fait cette fonction.

```c
void __fastcall __noreturn sub_138B(__int64 a1)
{
  char *v1; // rsi@4
  int v2; // eax@5
  int v3[97]; // [sp+10h] [bp-1A0h]@4
  unsigned int v4; // [sp+194h] [bp-1Ch]@5
  int v5; // [sp+198h] [bp-18h]@5
  int i; // [sp+19Ch] [bp-14h]@1

  for ( i = 0; i <= 4; ++i )
    dword_4060[i + 16LL] = sub_1355(*(_DWORD *)(4LL * i + a1));
  qmemcpy(v3, &unk_2020, 0x180uLL);
  v1 = (char *)&unk_2020 + 384;
  while ( 1 )
  {
    v5 = v3[dword_5064 + 1];
    v4 = v3[dword_5064 + 2];
    v2 = v3[dword_5064];
    if ( v2 == 2023406814 )
    {
      v1 = (char *)&dword_4060[v4];
      sub_1256(&dword_4060[v5], v1);
    }
    else if ( v2 <= 2023406814 )
    {
      if ( v2 == 1737075661 )
      {
        sub_1243((unsigned int)(3 * (v5 - 1)), v1);
      }
      else if ( v2 <= 1737075661 )
      {
        if ( v2 == 1450744508 )
        {
          sub_1207((unsigned int)(3 * (v5 - 1)), v1);
        }
        else if ( v2 <= 1450744508 )
        {
          if ( v2 == 1164413355 )
          {
            v1 = (char *)&dword_4060[v4];
            sub_11C1(&dword_4060[v5], v1);
          }
          else if ( v2 <= 1164413355 )
          {
            if ( v2 == 878082202 )
            {
              v1 = (char *)&dword_4060[v4];
              sub_119E(&dword_4060[v5], v1);
            }
            else if ( v2 <= 878082202 )
            {
              if ( v2 == 591751049 )
              {
                v1 = (char *)v4;
                sub_1170(&dword_4060[v5], v4);
              }
              else if ( v2 <= 591751049 )
              {
                if ( v2 == 305419896 )
                {
                  v1 = (char *)&dword_4060[v4];
                  sub_1155(&dword_4060[v5], v1);
                }
                else if ( v2 <= 305419896 )
                {
                  if ( v2 == -285138107 )
                  {
                    v1 = (char *)&dword_4060[v4];
                    sub_11E4(&dword_4060[v5], v1);
                  }
                  else if ( v2 <= -285138107 )
                  {
                    if ( v2 == -554692044 )
                    {
                      sub_1225((unsigned int)(3 * (v5 - 1)), v1);
                    }
                    else if ( v2 <= -554692044 )
                    {
                      if ( v2 == -839974621 )
                      {
                        v1 = (char *)&dword_4060[v4];
                        sub_12C6(&dword_4060[v5], v1);
                      }
                      else if ( v2 <= -839974621 )
                      {
                        if ( v2 == -1126240238 )
                        {
                          sub_1187(&dword_4060[v5], v1);
                        }
                        else if ( v2 <= -1126240238 )
                        {
                          if ( v2 == -1412567295 )
                            exit(status);
                          if ( v2 <= -1412567295 )
                          {
                            if ( v2 == -1985229329 )
                            {
                              v1 = (char *)(signed int)v4;
                              sub_127C(&dword_4060[v5], (signed int)v4);
                            }
                            else if ( v2 == -1698898192 )
                            {
                              v1 = (char *)(signed int)v4;
                              sub_12A1(&dword_4060[v5], (signed int)v4);
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    dword_5064 += 3;
  }
}
```

Hum, à première vu ça ressemble à un VM custom, `v2` serait l'opcode, `v3` le machine code, `v5` le premier paramètre passé aux fonctions, `v4` le second et `dword_5064` est l'instruction pointer. On commence par rename tout ça, par soucis de clarté.

Maintenant on s'attaque à la première partie de cette fonction.

```c
for ( i = 0; i <= 4; ++i )
    dword_4060[i + 16LL] = sub_1355(*(_DWORD *)(4LL * i + a1));

....

__int64 __fastcall sub_1355(signed int a1)
{
  return (((a1 << 8) & 0xFF00FF00 | (a1 >> 8) & 0xFF00FF) << 16) | (((a1 << 8) & 0xFF00FF00 | (a1 >> 8) & 0xFF00FF) >> 16);
}
```

Cette fonction sert tout simplement à "corriger" l'ordre des bytes d'un `DWORD`, en effet en little endian l'ordre des bytes n'est pas le même pour une `char[4]` que pour un `int`. Cela permettra donc de convertir votre input en `int[]` tout en gardant l'ordre d'origine.

```c
qmemcpy(assembly, &unk_2020, 0x180uLL);
```

On load le machine code dans une variable.

```c
 while ( 1 )
  {
    first_param = machine_code[instruction_pointer + 1];
    second_param = machine_code[instruction_pointer + 2];
    opcode = machine_code[instruction_pointer];
    if ( opcode == 2023406814 )
    {
    ...
```

Puis on commence notre boucle. Notre foret de if peut être remplacer par un switch case, ce qui rendrait le code plus lisible.

Nous avons plusieurs méthodes pour résoudre ce challenge, celle que j'ai choisi est la suivante:

Nous analysons chaque fonction, la plupart sont la réimplémentation d'operation basic, comme par exemple `sub_119E` qui xor les deux paramètres.

```c
_DWORD *__fastcall sub_119E(_DWORD *a1, _DWORD *a2)
{
  _DWORD *result; // rax@1

  result = a1;
  *a1 ^= *a2;
  return result;
}
```

Cependant une des fonctions sort du lots:

```c
_DWORD *__fastcall sub_12C6(_DWORD *a1, unsigned int *a2)
{
  _DWORD *result; // rax@6
  unsigned __int64 v3; // [sp+18h] [bp-18h]@1
  unsigned __int64 v4; // [sp+20h] [bp-10h]@1
  unsigned __int64 v5; // [sp+28h] [bp-8h]@1

  v5 = 1LL;
  v4 = dword_4074;
  v3 = *a1;
  while ( v4 )
  {
    if ( v4 & 1 )
      v5 = v3 * v5 % (signed int)*a2;
    v4 >>= 1;
    v3 = v3 * v3 % (signed int)*a2;
  }
  result = a1;
  *a1 = v5;
  return result;
}
```

`dword_4074` est une variable qui vaut `0x10001`, ce qui veut dire que la boucle s'effectura 17 fois (car `0x10001 >> 17 == 0` ou `log(0x10001, 2) > 16`).

On sait que la ligne `v5 = v3 * v5 % (signed int)*a2;` ne sera exécuté que deux fois car comme `dword_4074` peux être écris sous la forme `2^16 + 1`, donc `dword_4074 & 1` ne sera vrai que deux fois, lorsque que `dword_4074` est égale à 0x10001 ou 1.

La premier fois servant à initialiser `v5` à `v3` ou `*a1`.

Le seconde, après 16 tours de boucle, ou `v3` sera égale à `*a1 ^ (2 ^ 16)`.

Donc `v5` sera égale à `*a1 * *a1 ^ (2 ^ 16)`, ou `*a1 ^ (2 ^ 16 + 1)`, ou `*a1 ^ 0x10001`. Le tout bien sur modulo `*a2`.

La fonction pourra donc être réécrite en python tel que:

```python
def sub_12C6(a1, a2):
    return pow(a1, 0x10001, a2)
```

Certains l'auront sans doute remarqué, mais `0x10001` ou `65537` est l'exposant le plus répandu dans le cryptosystème RSA.

Cette fonction prend donc sûrement un plaintext et ainsi que un modulo pour chiffrer ce plaintext, sans doute d'ailleur que le retour de cette fonction sera comparé à une valeur dans le programme. Si on arrive à récupérer ces valeurs il sera donc peut-être possible de factoriser `a2` afin de récupérer la clé et trouver les valeurs attendu.

On créé un petit script qui nous affichera les fonctions appelé dans l'ordre avec quels valeurs.

```bash
$ python3 generate_asm.py
0:	       mov	   [0x4]	0x3
1:	       jmp	     0x4
2:	exit_value	 [0x3ff]
3:	      exit
4:	       mov	   [0x5]	0x10001
5:	       mov	 [0x100]	0x31420fa
6:	       mov	 [0x200]	0x77c7742d
7:	       mov	 [0x101]	0x2b74da6b
8:	       mov	 [0x201]	0x7d61e32d
9:	       mov	 [0x102]	0x638682bf
10:	       mov	 [0x202]	0x7b4dbc19
11:	       mov	 [0x103]	0x5941d721
12:	       mov	 [0x203]	0x62c26e5f
13:	       mov	 [0x104]	0x5ced41bb
14:	       mov	 [0x204]	0x686493f7
15:	       rsa	  [0x10]	[0x200]
16:	       cmp	  [0x10]	[0x100]
17:	       jnz	     0x2
18:	       rsa	  [0x11]	[0x201]
19:	       cmp	  [0x11]	[0x101]
20:	       jnz	     0x2
21:	       rsa	  [0x12]	[0x202]
22:	       cmp	  [0x12]	[0x102]
23:	       jnz	     0x2
24:	       rsa	  [0x13]	[0x203]
25:	       cmp	  [0x13]	[0x103]
26:	       jnz	     0x2
27:	       rsa	  [0x14]	[0x204]
28:	       cmp	  [0x14]	[0x104]
29:	       jnz	     0x2
30:	       mov	 [0x3ff]	0x1
31:	       jmp	     0x2
```

On peut voir qu'un certain nombres de valeurs sont chargé puis utilisés par la suite. Mais surtout que comme nous l'avons conjecturé, il y a génération du ciphertext à partir de l'entrée utilisateur puis comparaison.

On doit donc retrouver une entrée utilisateur validant les équations suivantes:

```python
pow(user_input[0], 65537, 0x77c7742d) == 0x31420fa
pow(user_input[1], 65537, 0x7d61e32d) == 0x2b74da6b
pow(user_input[2], 65537, 0x7b4dbc19) == 0x638682bf
pow(user_input[3], 65537, 0x62c26e5f) == 0x5941d721
pow(user_input[4], 65537, 0x686493f7) == 0x5ced41bb
```

`N` ou le 3ème paramètre de `pow`, est suffisament petit pour être factorisé rapidement, on peut donc retrouver `p` et `q`, générer `d` et retrouver le plaintext en faisant `pow(c, d, N)`.

On écrit donc un script pour faire cela pour nous:

```python
from Crypto.Util.number import long_to_bytes
from fractions import gcd
from gmpy2 import invert

def pollard_rho(n, seed=2, f=lambda x: x**2 + 1):
   x, y, d = seed, seed, 1
   while d == 1:
     x = f(x) % n
     y = f(f(y)) % n
     d = gcd((x - y) % n, n)
   return None if d == n else d

n_c = [
   (0x77c7742d, 0x31420fa),
   (0x7d61e32d, 0x2b74da6b),
   (0x7b4dbc19, 0x638682bf),
   (0x62c26e5f, 0x5941d721),
   (0x686493f7, 0x5ced41bb)
]
e = 2**16 + 1

for n, c in n_c:

   p = pollard_rho(n)
   q = n // p

   assert n == q * p

   phi = (p-1) * (q-1)

   d = invert(e, phi)

   assert (d * e) % phi == 1

   m = pow(c, d, n)
   print(long_to_bytes(m).decode(), end='')

print()
```

On le lance:

```bash
$ python3 solv_efficiency.py
sigsegv{VM3d_stuff!}
```

Et voilà ! Petit challenge vraiment sympa, merci à toute l'équipe RTFM pour avoir organisé ce CTF, on se retrouvera lors de la final.