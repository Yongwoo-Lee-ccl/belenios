from ring import *
from crypto import *
from belenios import *

def run():
    print("Welcome to Yongwoo's Belenois!\nType valid email address to enroll (press 0 to finish).")
    voters = dict()
    email = input().strip()
    while email != '0':
        if email in voters:
            print('Email [%s] exists try again.'%email)
        else:    
            voters[email] = Voter(email)
        email = input().strip()
    
    print("List of Voters:")
    for k in voters.keys():
        print("  ", k)

    print("Set cryptographic primitives...")
    q = 100000004987
    # q = 2**16 +1
    G = IntegersModP(q)
    signScheme = Signature(G)
    encScheme = Encryption(G)
    zkMemberScheme = ZeroKnowledgeMembership(G)
    zkScheme = ZeroKnowledgeDecrypt(G)

    print("Generating signing keys for each voters...")
    votingServer = VotingServer(voters)
    registrar = Registrar(voters)
    registrar.signKeygenAndDistribute(signScheme, votingServer)
    
    print("Setting up bulletin board...")
    votingServer.genPasswordsAndDistribute()

    print("Generating voting encryption keys...")
    trustee = DecryptionTurstee()
    trustee.encKeygenAndDistribute(encScheme, votingServer)

    instructionStr = """----------------------------------------
1: Vote
2: Bulletin board - see votes
3: Bulletin board - see vk lists
4: Bulletin board - see encryption keys
5: Verify ballot
0: Quit voting phase
----------------------------------------
"""
    command = input(instructionStr)

    while command != '0':
        if command == '1':
            print('ID:') # assume voter remembers password
            id = input()
            if id not in voters.keys():
                print('invalid id')
                continue

            print('Your vote: (0/1)')
            v = int(input())
            voters[id].vote(v, votingServer, encScheme, zkMemberScheme, signScheme)
        elif command == '2':
            ballots = votingServer.communicate('getBallots')
            for id in ballots.keys():
                print("id: %s\n\tc: %s\n\tpi: %s\n\ts: %s\n\tvk: %s\n\t"%(id, *(ballots[id][0]), ballots[id][1]))
        elif command == '3':
            votingServer.communicate('getVerifKeys')
        elif command == '4':
            votingServer.communicate('getEncryptionPublicKey')
        elif command == '5':
            # verify signature
            print('Verify signature')
            a, b = input('Ciphertext a b:').split()
            ct = (G(int(a)), G(int(b)))
            r, c = input('signature r c: ').split()
            sgn = (int(r),int(c))
            vk = G(int(input('verification key: ')))
            
            ver = signScheme.verifsign(ct, sgn, vk)
            print(ver)
            # verify zk (membership)
        else:
            print("command [%s] invalid"%command)

        command = input(instructionStr)
    
    print('Tally: performing homomorphic additions...')
    resEnc = votingServer.communicate('getResultEnc')
    print('Encryped result is:', resEnc)

    print('Trustee is decrypting ciphertext...')
    v, proof = trustee.decryptAndProof(resEnc, encScheme, zkScheme, votingServer)
    print('Final result:', v, 'and its proof:', proof)
    
    print('Verifying proof...')
    g = G(G.gen)
    gv = g**v

    a, b = resEnc
    C = a
    M = b/gv # M = C**sk
    pk = votingServer.communicate('getEncryptionPublicKey')
    result = zkScheme.verify(pk, M, C, proof)

    print('The proof is', result)
    
if __name__ == '__main__':
    run()



