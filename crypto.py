from ring import *
from hashlib import sha256
from collections.abc import Iterable   # import directly from collections for Python < 3.3

INT_LEN = 64

def hash(mod, *args):
    msg = bytearray()
    for arg in args:
        if not isinstance(arg, int): #then it is elem of G
            arg = arg.n
        msg += (arg%mod).to_bytes(INT_LEN, 'little')
    digest = sha256(msg).digest()
    return (int.from_bytes(digest, 'little'))%mod

class Encryption():
    def __init__(self, G):
        self.G = G
        self.g = G(G.gen)

    def keygen(self):
        sk = self.G.randomInt()
        pk = self.g ** sk
        return (sk, pk)

    def enc(self, msg, pk, r=None):
        msg %= self.G.phi

        g = self.g
        if r == None:
            r = self.G.randomInt()
        return (g**r, pk**r * g**msg)
        
    def dec(self, ct, sk):
        g = self.g

        a,b = ct
        gv = b/(a**sk)
        return gv

    def distLog(self, gv):
        # naive disc. log for `small' v
        g = self.g

        v = 0
        powg = self.G(1)
        while powg != gv:
            powg *= g
            v += 1
        return v

class Signature():
    def __init__(self, G):
        self.G = G
        self.g = G(G.gen)
    
    def keygen(self):
        sk = self.G.randomInt()
        vk = self.g ** sk
        return (sk, vk)
    
    def sign(self, msg, sk, w=None):
        if w == None:
            w = self.G.randomInt()
        gw = self.g ** w
        if isinstance(msg, Iterable):
            c = hash(self.G.phi, *msg, gw)
        else:
            c = hash(self.G.phi, msg, gw)
        r = (w - sk * c)%self.G.phi
        return r,c

    def verifsign(self, msg, sgn, vk):
        r, c = sgn
        A = (self.g ** r) * (vk ** c)
        if isinstance(msg, Iterable):
            digest = hash(self.G.phi, *msg, A)
        else:
            digest = hash(self.G.phi, msg, A)
        if c == digest:
            return True
        return False

class ZeroKnowledgeDecrypt():
    def __init__(self, G):
        self.G = G
        self.g = G(G.gen)
    
    def proof(self, h, M, C, x): 
        g = self.g
        phi = self.G.phi

        k = self.G.randomInt()
        A = g**k
        B = C**k

        # Challenge e (Fiat-Shamir)
        e = hash(phi, g, h, C, M, A, B)

        # Response
        s = k + x*e
        s %= phi

        return A, B, s # e is not in proof, it is hash
    
    def verify(self, h, M, C, proof):
        g = self.g
        phi = self.G.phi

        A, B, s = proof

        e = hash(phi, g, h, C, M, A, B)

        if A != g**s * h**(-e):
            return False
        if B != C**s * M**(-e):
            return False

        return True


class ZeroKnowledgeMembership():
    def __init__(self, G):
        self.G = G
        self.g = G(G.gen)
    
    def proofv(self, h, ct, M, r, m): 
        # h: public key, 
        # m: message following the notation in paper, 
        # M: set of valid values {M0, ..., Mk}, assume M = [0,k] here
        alpha, beta = ct
        g = self.g
        phi = self.G.phi

        k = len(M) # 0, ..., k-1
        sigma = [0]*k
        rho = [0]*k
        A = [0]*k
        B = [0]*k

        for j in range(k):
            if m == j:
                continue

            sigma[j] = self.G.randomInt()
            rho[j] = self.G.randomInt()

            A[j] = g**rho[j] * alpha**(-sigma[j])
            B[j] = h**rho[j] * (beta/(g**j))**(-sigma[j])#Mj =j

        w = self.G.randomInt()
        A[m] = g**w
        B[m] = h**w
        
        # Challenge e (Fiat-Shamir)
        e = hash(phi, g, h, alpha, beta, *A, *B)

        # Response
        sigma[m] = e
        for j in range(k):
            if m == j:
                continue
            sigma[m] -= sigma[j]
        sigma[m] %= phi
        
        rho[m] = w + r*sigma[m]
        rho[m] %= phi

        return A, B, sigma, rho
    
    def verifyv(self, h, ct, M, proof):
        g = self.g
        phi = self.G.phi

        A, B, sigma, rho = proof
        alpha, beta = ct
        e = hash(phi, g, h, alpha, beta, *A, *B)

        # check e = sum sigma_j
        if e != sum(sigma)%phi:
            return False

        k = len(M)

        for j in range(k):
            if A[j] != g**rho[j] * alpha**(-sigma[j]):
                return False
            if B[j] != h**rho[j] * (beta/(g**j))**(-sigma[j]):
                return False

        return True


