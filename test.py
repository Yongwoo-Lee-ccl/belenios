from crypto import *

q = 2**16 + 1
G = IntegersModP(q)

encScheme = Encryption(G)
sk, pk = encScheme.keygen()
m = 1
r = G.randomInt()
ct = encScheme.enc(m, pk, r)
print('r:', r)

signScheme = Signature(G)
sgnk, vk = signScheme.keygen()
print(isinstance(vk, G))
print('signing keys: %s, %s'%(sgnk, vk))
sgn = signScheme.sign(m, sgnk)
ver = signScheme.verifsign(m, sgn, vk)
print('sign(not iterable):', m, sgn, ver)

miter = (1,2,3)
sgn = signScheme.sign(miter, sgnk)
ver = signScheme.verifsign(miter, sgn, vk)
print('sign(iterable):', miter, sgn, ver)

a, b = ct
gv =  encScheme.dec(ct, sk) # gv = b/(a**sk) -> (a**sk) = b/gv = b/ (b/a**sk)
C = a
M = b/gv # M = C**sk

zkScheme = ZeroKnowledgeDecrypt(G)
proof = zkScheme.proof(pk, M, C, sk)

print(encScheme.distLog(gv), m)
print(proof)

result = zkScheme.verify(pk, M, C, proof)
print(result)

zkMemberScheme = ZeroKnowledgeMembership(G)
members = range(2)
proof = zkMemberScheme.proofv(pk, ct, members, r, m)
result = zkMemberScheme.verifyv(pk, ct, members, proof)
print(proof)
print(result)