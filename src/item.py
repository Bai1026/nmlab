import os
import json
from basic import createRandomString, generateKeyPair, createUniqueDID
class Item:
    def __init__(self, owner):

        self.owner = owner
        self.id = createUniqueDID()

        dataFolder = "../data"
        self.ownerFolder = os.path.join(dataFolder, self.owner)
        print(self.ownerFolder)
        if not os.path.isdir(self.ownerFolder):
            os.mkdir(self.ownerFolder)
            os.mkdir(self.ownerFolder+"/localStorage")
            os.mkdir(self.ownerFolder+"/TPM")

        privateKeysFile = os.path.join(self.ownerFolder, "TPM", self.id+".key")
        self.publicKey = generateKeyPair(privateKeysFile)

        self.DID = {}
        self.DID["@context"] = [
            "https://www.w3id.org/did/v1"
        ]
        self.DID["id"] = self.id

        self.DID["publicKey"] = []
        publicKey = {}
        publicKey["id"] = self.publicKey
        publicKey["type"] = "RsaSignatureAuthentication2022"
        publicKey["owner"] = self.id
        publicKey["publicKeyPem"] = "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n"
        self.DID["publicKey"].append(publicKey)

        self.DID["authentication"] = []
        authentication = {}
        authentication["type"] = "RsaSignatureAuthentication2022"
        authentication["publicKey"] = self.publicKey
        self.DID["authentication"].append(authentication)

        self.DID["service"] = [
            {
                "type": "VerifiableCredentialService",
                "serviceEndpoint": "https://example.com/vc/"
            }
        ]

        ##### write did into storage/blockchain #####

        didFile = os.path.join(self.ownerFolder, "localStorage", self.id+".json")
        blockChainFile = "../blockChain/dids.json"

        did = json.dumps(self.DID)
        with open(didFile, "w") as outfile:
            outfile.write(did)

        dids = "nothing"
        with open(blockChainFile, "r") as infile:
            temp = json.load(infile)
            temp[self.id] = self.DID
            dids = json.dumps(temp)
        with open(blockChainFile, "w") as outfile:
            outfile.write(dids)

        print("new item added")