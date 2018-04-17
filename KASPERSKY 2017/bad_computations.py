from random import choice
from sys import argv
from base64 import b64encode, b64decode


b = 22


def primes_in_range(x, z):
    primes = []
    for a in range(x, z + 1):
        for i in range(2, a):
            if (a % i) == 0:
                break
        else:
            primes.append(a)

    return primes


def candidates(max_n):
    good_candidates = [x for x in range(2, max_n)]

    x = 2
    swipe_cont = True
    while swipe_cont:
        for i in range(x * x, max_n, x):
            if i in good_candidates:
                good_candidates.remove(i)

        swipe_cont = False
        for i in good_candidates:
            if i > x:
                x = i
                swipe_cont = True
                break

    return good_candidates


def gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd_except(a, m):
    g, x, y = gcd(a, m)
    if g != 1:
        raise Exception('Oops! Error!')
    else:
        return x % m

def L(u, n):
    return (u - 1) // n


def main():
    print("Key cryptor v1.0")

    if len(argv) != 2:
        print("Start script like: python crypt.py <YourOwnPasswordString>")

    if (not str(argv[1]).startswith("KLCTF{")) or (not str(argv[1]).endswith("}")):
        print("Error! Password must starts with KLCTF")
        exit()

    p = choice(primes_in_range(100, 200))
    q = choice(primes_in_range(200, 300))

    print("Waiting for encryption...")

    n = p * q
    print n
    g = None
    '''
    for i in xrange(n + 1, n * n):
        if ((i % p) == 0) or ((i % q) == 0) or ((i % n) == 0):
            continue

        g = i
        break
    '''

    g = n + 1

    if g is None:
        print("Error! Can't find g!")
        exit()

    lamb = (p - 1) * (q - 1)
    mu = gcd_except(L(pow(g, lamb, n * n), n), n) % n

    rc = candidates(n - 1)
    if len(rc) == 0:
        print("Error! Candidates for r not found!")
        exit()

    if p in rc:
        rc.remove(p)
    if q in rc:
        rc.remove(q)

    r = choice(rc)

    listed_pass = [ord(x) for x in argv[1][6:-1]]
    multp = (pow(g, b, (n * n)) * pow(r, n, (n * n))) % (n * n) # b = 22

    for i in range(len(listed_pass)):
        listed_pass[i] = (((pow(g, listed_pass[i], (n * n)) * pow(r, n, (n * n))) % (n * n)) * multp) % (n * n)
        listed_pass[i] = (L(pow(listed_pass[i], lamb, (n * n)), n) * mu) % n
    print listed_pass
    listed_pass = b64encode(bytearray(listed_pass))
    print(str(listed_pass)[2:-1])

# main()

listed_pass = 'hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA=='
listed_pass = b64decode(listed_pass)
ords =  [ord(x) for x in listed_pass]
listed_pass = ''.join([chr(x - 119 + ord('a')) for x in ords])
print listed_pass