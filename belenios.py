from random import randrange

class Registrar():
    def __init__(self, _voters):
        self.voters = _voters

    def signKeygenAndDistribute(self, signScheme, votingServer):
        self.skMap = dict()
        self.vkMap = dict()
        for id in self.voters.keys():
            sk, vk = signScheme.keygen()
            self.skMap[id] = sk
            self.vkMap[id] = vk
            self.voters[id].communicate('signkeys', sk, vk)
        
        votingServer.communicate('vkLists', self.vkMap)

class Voter():
    def __init__(self, _id):
        self.id = _id

    def vote(self, m, votingServer, encScheme, zkMemberScheme, signScheme):
        pk = votingServer.communicate('getEncryptionPublicKey')
        r = encScheme.G.randomInt()
        ct = encScheme.enc(m, pk, r)
        
        members = range(2)
        pi = zkMemberScheme.proofv(pk, ct, members, r, m)

        s = signScheme.sign(ct, self.signsk)

        votingServer.communicate('vote', self.id, self.loginPwd, (ct, pi, s), self.signvk)

    def communicate(self, prefix, *args):
        print("[Communication] Voter [%s] accepted [%s] with %s"%(self.id, prefix, args))
        if prefix == 'signkeys':
            self.signsk = args[0]
            self.signvk = args[1]
        elif prefix == 'loginPassword':
            self.loginPwd = args[0]
    
class VotingServer():
    def __init__(self, _voters):
        self.voters = _voters
        self.bulletin = dict() # (vote, vk)
        self.resEnc = None
        self.result = None

    def communicate(self, prefix, *args):
        if prefix == 'vkLists':
            self.vkList = args[0] # a.k.a. log in the paper

        elif prefix == 'setEncryptionPublicKey':
            self.pk = args[0]

        elif prefix == 'getEncryptionPublicKey':
            # print(self.pk) 
            return self.pk

        elif prefix == 'getVerifKeys':
            print(self.vkList)

        elif prefix == 'vote':
            userID = args[0]
            userPw = args[1]
            if self.pwdMap[userID] != userPw:
                print("Wrong password!")
                return None
            ballot = args[2]
            vk = args[3]
            if userID in self.bulletin.keys():
                if self.bulletin[userID][1] != vk:
                    print("Wrong verification keys!")
                    return None
            for key in self.bulletin.keys():
                if self.bulletin[key][1] == vk and key != userID:
                    print("Other voter used the verification key!")
                    return None
            self.bulletin[userID] = (ballot, vk)

        elif prefix == 'getBallots':
            return self.bulletin

        elif prefix == 'getResultEnc':
            if self.resEnc == None:
                self.resultEncryption()
            return self.resEnc

        elif prefix =='publishDecryption':
            res = args[0]
            proof = args[1]

            self.result = (res, proof)

        elif prefix == 'getDecryption':
            return self.result
        
    def genPasswordsAndDistribute(self):
        self.pwdMap = dict()
        for id in self.voters.keys():
            pwd = randrange(1000000) # 6-digit random int password
            self.pwdMap[id] = pwd
            self.voters[id].communicate('loginPassword', pwd)

    def resultEncryption(self):
        aprod, bprod = None, None

        for id in self.bulletin.keys():
            a, b = self.bulletin[id][0][0]
            if aprod == None:
                aprod = a 
                bprod = b 
            else:
                aprod *= a 
                bprod *= b

        self.resEnc = (aprod, bprod)

    def vkList(self):
        return self.vkList

class DecryptionTurstee():
    def __init__(self):
        pass

    def encKeygenAndDistribute(self, encScheme, votingServer):
        sk, pk = encScheme.keygen()
        self.sk = sk
        self.pk = pk
        votingServer.communicate('setEncryptionPublicKey', pk)

    def decryptAndProof(self, ct, encScheme, zkScheme, votingServer):
        a, b = ct
        gv =  encScheme.dec(ct, self.sk) # gv = b/(a**sk) -> (a**sk) = b/gv = b/ (b/a**sk)
        v = encScheme.distLog(gv)

        C = a # following to notation in paper
        M = b/gv # M = C**sk

        proof = zkScheme.proof(self.pk, M, C, self.sk)
        votingServer.communicate('publishDecryption', v, proof)

        return v, proof
