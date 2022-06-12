from ring import *
from crypto import *
from belenios import *

def run():
    print("Welcome to Yongwoo's Belenois!\nType valid email address to enroll (press q to finish).")
    voters = dict()
    email = input().strip()
    while email != 'q':
        if email in voters:
            print('Email [%s] exists try again.'%email)
        else:    
            voters[email] = Voter(email)
        email = input().strip()
    
    print("List of Voters:")
    for k in voters.keys():
        print("  ", k)

    print("Set cryptographic primitives...")
    q = 2**16 +1
    Zq = IntegersModP(q)
    signScheme = Signature(Zq)
    encScheme = Encryption(Zq)

    print("Generating signing keys for each voters...")
    votingServer = VotingServer(voters)
    registrar = Registrar(voters)
    registrar.signKeygenAndDistribute(signScheme, votingServer)
    
    print("Setting up bulletin board...")
    votingServer.genPasswordsAndDistribute()

    print("Generating voting encryption keys...")
    trustee = DecryptionTurstee()
    trustee.encKeygenAndDistribute(encScheme, votingServer)

    instructionStr = """
----------------------------------------
1: Vote
2: Bulletin board - see votes
3: Bulletin board - see vk lists
4: Bulletin board - see encryption keys
5: Verify ballot
0: Quit voting phase
----------------------------------------
    """
    print(instructionStr)
    command = input()

    while command != '0':
        if command == '1':
            print('ID:') # assume voter remembers password
            id = input()
            print('Your vote: (0/1)')
            v = int(input())
            voters[id].vote(v)

        elif command == '2':
            pass
        elif command == '3':
            votingServer.communicate('getVerifKeys')
        elif command == '4':
            votingServer.communicate('getEncryptionPublicKey')
        else:
            print("command [%s] invalid"%command)

        print(instructionStr)
        command = input()

if __name__ == '__main__':
    run()



