# Networking and Multimedia Lab

> Code Explain

* Under "./data", there are several owners, and each owner has two directories:
    1. localStorage is used to store "DID"
    2. TPM is used to store "DID-privateKey" and "vc"
* owner.py: 
    1. create a new owner
    2. create directory
    3. create keypair, and save private one in TPM
    4. create did document, and save it in localStorage and blockchain
* item.py:
    1. create a new item
    2. create keypair, and save private one in TPM
    3. create did document, and save it in localStorage and blockchain
* vc.py:
    1. VC_transfer
    2. VC_revoke

> How to execute?

1. go to directory pi@raspberrypi:~/nmlab/src
2. type `python main.py`

* The format of input statement:
1. if you want factory A to create a new item, please input `createAnItem factory_A_did`
2. if the ownership of item I is transfered from organization A to organization B and having an issuer C,   please input `transfer organization_A_did organization_B_did issuer_C_did item_I_did `
3. if a gun is assembled by item 1, item 2, item 3 in the facory A and having an issuer C, please input `assemble factory_A_did issuer_C_did item_I1_did item_I2_did item_I3_did`
4. if the item I need to be revocated, please input `revoke organization_A_did item_I_did`

>The discription of VC type:
1. transfer (A sells i to D):
    * holder: A
    * issuer: MOD
    * verifier: D
    * (issuer encrypt doc with own private key)
    * (holder decrypt doc with issuer's public key)
    * system generate the current time
    * holder "sign" vc with own private key 
    * verifier "verify" vc with holder's public key
    * add vc(related to i)/private key from holder's TPM to verifier's TPM 
    * remove i's DID from holder's localStorage

2. revoke (Army revokes i):
    * holder: Army
    * issuer: MOD
    * verifier: MOD
    * (issuer encrypt doc with own private key)
    * (holder decrypt doc with issuer's public key)
    * holder encrypt vc with own private key 
    * verifier decrypt vc with holder's public key
    * remove vc(related to i)/private key from holder's TPM
    * remove i's DID from holder's localStorage# nmlab
