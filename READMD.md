# Belenios implementation over python

This is an simple simulation of e-voting system Belenious.
It is just simulator, so not ready to use in real voting.
For the full implementation, visit [here](https://www.Belenios.org/).

## How to run
```shell
python interface.py
```
Follow the instruction of programming, it is easy to follow.
## Class explanation
### ring.py

We use dicisional Diffie-Hellman as cryptographic primitives.
So we need a cyclic group G of order q.
We use Z_q* for prime q as G and its order is q-1.

Following code returns class G
```python
G = IntegersModP(q)
```
and 
```python
G.gen
```
returns its generator.

All the integer operators are overloaded.

### crypto.py
This file includes cryptogrphic algorithms needed in Belenios.

* (Additive homomorphic) Encryption
    ```python
    encScheme = Encryption(G)
    ```
    The class has following methods: key generation, encryption, and decryption.

* Digital signature
    ```python
    signScheme = Signature(G)
    ```
    The class has following methods: key generation, signing, and verification.

* Zero-knowledge proof
    * Zero-knowledge of valid decryption
        ```python
        zkScheme = ZeroKnowledgeDecrypt(G)
        ```
        The class has following methods: proof and verification.

    * Zero-knowledge of membership of plaintext
        ```python
        zkMemberScheme = ZeroKnowledgeMembership(G)
        ```
        The class has following methods: proof and verification.

### Belenios.py
Four classes for participants in Belenios is implemented: registrar, voting server, decryption trustee, and voter.

Following method in VotingServer and Voter simulates communication between the object and caller.
```python
communicate(self, prefix, *args)
```

* Registrar:

    Provides list of voters and generates signing key of them

* DecryptionTrustee(s):

    Generates decryption key and encryption key for voting; decrypts final results with proof of valid decryption.
    
    (Optional, not implemented here) a threshold encryption can be used with multiple trustees.

* VotingServer:

    maintains bulletin board; provides all the public values so that anyone can verify ballots and results anytime

* Voters: 

    vote; each ballot includes encrypted ballot, proof of membership of legitimate message, and signature

### interface.py
Main provides command line interface.
