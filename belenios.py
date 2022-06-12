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
            self.voters[id].communicate('signsk', sk)
        
        votingServer.communicate('vkLists', self.vkMap)
        

class Admin():
    def __init__(self):
        pass

class Voter():
    def __init__(self, _id):
        self.id = _id

    def vote(self, v, votingServer, encScheme, zkvScheme, signScheme):
        pk = votingServer.communicate('getEncryptionPublicKey')
        r = encScheme.Zq.randomInt()
        ct = encScheme.enc(v, pk, r)

    def communicate(self, prefix, *args):
        print("[Communication] Voter [%s] accepted [%s] with %s"%(self.id, prefix, args))
        if prefix == 'signsk':
            self.signsk = args[0]
        elif prefix == 'loginPassword':
            self.loginPwd = args[0]
    
class VotingServer():
    def __init__(self, _voters):
        self.voters = _voters

    def communicate(self, prefix, *args):
        if prefix == 'vkLists':
            self.vkList = args[0] # a.k.a. log in the paper
        elif prefix == 'setEncryptionPublicKey':
            self.pk = args[0]
        elif prefix == 'getEncryptionPublicKey':
            print(self.pk) 
            return self.pk
        elif prefix == 'getVerifKeys':
            print(self.vkListStr())
        elif prefix == 'login':
            emailInput = args[0]
            pwInput = args[1]
        
    def genPasswordsAndDistribute(self):
        self.pwdMap = dict()
        for id in self.voters.keys():
            pwd = randrange(1000000) # 6-digit random int password
            self.pwdMap[id] = pwd
            self.voters[id].communicate('loginPassword', pwd)

    def vkList(self):
        return self.vkList

    def vkListStr(self):
        table = 'id\tvrifkey\n-----------------\n'
        for id in self.vkList.keys():
            table += '%s\t%s\n'%(id, self.vkList[id])
        return table


class DecryptionTurstee():
    def __init__(self):
        pass

    def encKeygenAndDistribute(self, encScheme, votingServer):
        sk, pk = encScheme.keygen()
        self.sk = sk
        self.pk = pk
        votingServer.communicate('setEncryptionPublicKey', pk)

