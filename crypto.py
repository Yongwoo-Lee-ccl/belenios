from ring import *
from hashlib import sha256
INT_LEN = 64

def hash(mod, *args):
    msg = bytearray()
    for arg in args:
        msg += (arg%mod).to_bytes(INT_LEN, 'little')
    digest = sha256(msg).digest()
    return (int.from_bytes(digest, 'little'))%mod

class Encryption():
    def __init__(self, Zq):
        self.Zq = Zq
        self.g = Zq(Zq.gen)

    def keygen(self):
        sk = self.Zq.randomInt()
        pk = self.g ** sk
        return (sk, pk)

    def enc(self, msg, pk):
        msg %= self.Zq.phi

        g = self.g
        r = self.Zq.randomInt()
        return (g**r, pk**r * g**msg)
        
    def dec(self, ct, sk):
        g = self.g

        a,b = ct
        gv = b/(a**sk)
        # naive disc. log for `small' v
        v = 0
        powg = self.Zq(1)
        while (powg).n != gv.n:
            powg *= g
            v += 1
        return v

class Signature():
    def __init__(self, Zq):
        self.Zq = Zq
        self.g = Zq(Zq.gen)
    
    def keygen(self):
        sk = self.Zq.randomInt()
        vk = self.g ** sk
        return (sk, vk)
    
    def sign(self, msg, sk):
        w = self.Zq.randomInt()
        gw = self.g ** w
        c = hash(self.Zq.phi, msg, gw.n)
        r = (w - sk * c)%self.Zq.phi
        return r,c

    def verifsign(self, msg, sgn, vk):
        r, c = sgn
        A = (self.g ** r) * (vk ** c)
        digest = hash(self.Zq.phi, msg, A.n)
        if c == digest:
            return True
        return False


