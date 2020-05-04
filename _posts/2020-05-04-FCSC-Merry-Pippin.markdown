---
layout: post
title:  "Merry and Pipin"
date:   2020-05-04 07:20:14 +0200
categories: writeup
---

# FCSC

## Crypto

### Merry

Nous nous retrouvons face à un service d'échange de clés. Lorsque nous nous connectons le programme nous envoie deux matrices, `A` et `B`, et nous propose trois options: 
- un échange de clé 
- une vérification des matrics secrètes
- et tous simplement de quitter le programme

Le programme nous étant fournis nous commençons tout d'abors par en lire les sources.

----------

#### Énumération:

Plusieurs valeurs sont définis dedans et seront utiles par la suite
```python
q     = 2 ** 11
n     = 280
n_bar = 4
m_bar = 4
```
De plus lors de l'initialisation du servers plusieurs matrices sont générés
```python
self.__S_a = np.matrix(np.random.randint(-1, 2, size = (self.n, self.n_bar)))
self.__E_a = np.matrix(np.random.randint(-1, 2, size = (self.n, self.n_bar)))
self.A     = np.matrix(np.random.randint( 0, q, size = (self.n, self.n)))
self.B     = np.mod(self.A * self.__S_a + self.__E_a, self.q)
```
`__S_a` et `__E_a` sont les deux matrices secrètes qu'il nous faudra retrouver, elle sont de dimensions `(280, 4)` et composés de valeurs comprises entre `[-1, 1]` choisies de manière random.
`A` et `B` sont les deux matrices qui nous sont envoyés à l'initialisation, on constate aussi que `B` est composé à partir de `A`, `__S_a`, `__E_a` et `q`.

Revenons maintenant au menu, les deux choix qui nous intéressent ici sont l'échange de clés ainsi que la vérification des matrices secrètes.

La vérification nous demande les deux clés secrètes, les compares aux originales et nous affiche le flag si les égalités sont vrais
```python
def check_sk(self, S_a, E_a):
    return (S_a == self.__S_a).all() and (E_a == self.__E_a).all()


S_a = np.reshape(np.frombuffer(decompress(b64d(input("S_a = "))), dtype = np.int64), (n, n_bar))
E_a = np.reshape(np.frombuffer(decompress(b64d(input("E_a = "))), dtype = np.int64), (n, n_bar))

if server.check_sk(S_a, E_a):
    print("Correct key, congratulations! Here is the flag: {}".format(flag))
else:
    print("Sorry, this is not the correct key.")
    print("Bye bye.")
    exit(1)
```

L'échange de clés demande tout d'abord trois matrices à l'utilisateur, `U`, `C` et `key_b`.
```python
U     = np.reshape(np.frombuffer(decompress(b64d(input("U = "))), dtype = np.int64), (m_bar, n))
C     = np.reshape(np.frombuffer(decompress(b64d(input("C = "))), dtype = np.int64), (m_bar, n_bar))
key_b = np.reshape(np.frombuffer(decompress(b64d(input("key_b = "))), dtype = np.int64), (m_bar, n_bar))
```
Ces matrices passeront une série d'opérations et un test dont le résultats nous sera renvoyé.
```python
def __decode(self, mat):
    def recenter(x):
        if x > self.q // 2:
            return x - self.q
        else:
            return x

    def mult_and_round(x):
        return round((x / (self.q / 4)))

    out = np.vectorize(recenter)(mat)
    out = np.vectorize(mult_and_round)(out)
    return out

def __decaps(self, U, C):
    key_a = self.__decode(np.mod(C - np.dot(U, self.__S_a), self.q))
    return key_a

def check_exchange(self, U, C, key_b):
    key_a = self.__decaps(U, C)
    return (key_a == key_b).all()


if server.check_exchange(U, C, key_b):
    print("Success, the server and the client share the same key!")
else:
    print("Failure.")
```

----------

#### Vulnérabilité:

Nous voyons que `key_a` est généré à partir de nos matrices `C` et `U` ainsi que la matrice secrète `__S_a` puis comparé à `key_b`
La première idée qui nous vient à l'esprit est de bruteforce l'égalité jusqu'à retrouver `__S_a`, cependant, pour un matrice de dimension `(280, 4)`, ayant trois états différents pour chaques éléments, cela revient à tester `3 ^ (4 * 280)` possibilités.
Tout de suite nous repéront cette ligne `np.dot(U, self.__S_a)`, en effet en envoyant une matrice avec pour seul élément non zéro `U[0,i] = 1` le produit scalaire de `U` et `__S_a` renverait une matrice vide, sauf pour la première rangé égale à la rangé `i` de `__S_a`. Grâce à cela nous n'avons plus que `(3 ^ 4) * 280` possibilités à tester.

Nous commençons donc à écrire notre solveur.
Nous avons donc besoin d'envoyer `U` avec pour seul élément non zéro `U[0,i] = 1`, `C` avec pour première ligne la ligne `i` de `S_a` testé et pour finir une matrice zéro pour `key_b`.
```python
S_a = np.zeros((n, n_bar), dtype = np.int64)

for i in range(n):
    print("line:", i)
    U = np.zeros((m_bar, n), dtype = np.int64)
    C = np.zeros((m_bar, n_bar), dtype = np.int64)
    key_b = np.zeros((m_bar, n_bar), dtype = np.int64)
    U[0, i] = 1
    for line in itertools.product([-1, 0, 1], repeat=4):
        C[0] = line
        if check_exchange(encode(U), encode(C), encode(key_b)):
            S_a[i] = line
            break
```
Après l'avoir testé en local nous nous rendons comptes qu'il reste un problème, en effet `key_a` passe par la fonction `__decode` avant d'être comparé.
Cette fonction applique deux opération sur chaques élément de `key_a`, le premier ne nous intéresse peu mais le deuxième divise chaque élément par `self.q / 4` ou `512.0` et l'arrondie.
`-1`, `0` et `1` seront tous égaux à `0` une fois divisé par `512.0` il nous faut donc trouver une valeur donnant des résultats différents.
Avec une seul requête cela n'est pas possible, mais avec deux nous pouvons tout d'abord les éléments égaux à `-1` puis ceux à `1`, ceux restant étant forcément égaux à `0`.
Pour cela nous devont faire en sorte que le résultat de `np.mod(C - np.dot(U, self.__S_a), self.q)` soit dans les ranges `[255, 257]` pour tester `-1` et `[256, 258]` pour tester `1`.
Pour cela nous devons initialiser `C[0]` à `[256, 256, 256, 256]` dans la première et à `[257, 257, 257, 257]` dans la deuxième, puis initialiser `key_b[0][x]` à `line[x] < 0` pour la première et `line[x] < 1` pour la deuxième.

Un fois codé cela ressemblera à ça:
```python
S_a = np.zeros((n, n_bar), dtype = np.int64)

for i in range(n):
    U = np.zeros((m_bar, n), dtype = np.int64)
    C = np.zeros((m_bar, n_bar), dtype = np.int64)
    key_b = np.zeros((m_bar, n_bar), dtype = np.int64)
    U[0, i] = 1
    print("line:", i)
    for line in itertools.product([-1, 0, 1], repeat=4):
        C[0] = [256, 256, 256, 256]
        key_b[0] = [ int(_ < 0) for _ in line ]
        c1 = check_exchange(encode(U), encode(C), encode(key_b))

        C[0] = [257, 257, 257, 257]
        key_b[0] = [ int(_ < 1) for _ in line ]
        c2 = check_exchange(encode(U), encode(C), encode(key_b))

        if c1 and c2:
            S_a[i] = line
            break
```

Il nous suffit donc juste de retrouver `__E_a` et nous pourrons récupérer le flag.
Pour rappel `B` est généré à partir de `A`, `__S_a`, `__E_a` et `q`
```python
self.B     = np.mod(self.A * self.__S_a + self.__E_a, self.q)
```

Nous pouvons juste faire `np.mod(B - A * S_a, q)`  afin de retrouver `__E_a`, sans oublier bien remplacer les éléments de `__E_a` égaux à `p - 1`, car `-1 ≡ q - 1 [q]`.

```python
tmp = np.mod(B - A * S_a, q)
E_a = np.where(tmp==q-1, -1, tmp)
```

Nous mettons tous ça en place, attendons quarante-deux minutes et récupérons le flag.

----------

### Pippin

Pippin est la suite de Merry avec quelques différences, les lignes de `__S_a` sont générés différemment et le nombre d'échange de clés est limité.

Pour commencer nous découvrons comment est généré en lançant notre script précédant. Nous voyons alors que chaque rangé de `__S_a` est composé de un `-1`, deux `0` et un `1` et nous conjecturons que c'est le cas peu importe la ligne.
Ce nous permet de calculer chaque ligne en au maximum `7` requêtes, soit `7 * 280` requêtes au total.
Ce nombre étant bien en dessous des `3000` authorisés, nous écrivons notre solveur.

```python
for i in range(n):
    print("line:", i)
    U = np.zeros((m_bar, n), dtype = np.int64)
    C = np.zeros((m_bar, n_bar), dtype = np.int64)
    key_b = np.zeros((m_bar, n_bar), dtype = np.int64)
    U[0, i] = 1
    c1 = None
    c2 = None
    for x in range(4):
        C[0] = [256, 256, 256, 256]
        key_b[0][x] = 1

        if check_exchange(encode(U), encode(C), encode(key_b)):
           c1 = x

        else:
            C[0] = [257, 257, 257, 257]
            key_b[0] = [1, 1, 1, 1]
            key_b[0][x] = 0

            if check_exchange(encode(U), encode(C), encode(key_b)):
                c2 = x

        if c1 is not None and c2 is not None:
            line = np.zeros((n_bar), dtype = np.int64)
            line[c1] = -1
            line[c2] = 1
            S_a[i] = line
            break
```

Le reste n'a pas changé, nous pouvons donc lancer notre script et récupérer le flag.
