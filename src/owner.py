import os
import json
from basic import generateKeyPair


class Owner:
    def __init__(self, did):
        dataFolder = "../data"
        self.did = did
        self.ownerFolder = os.path.join(dataFolder, self.did)
        if not os.path.isdir(self.ownerFolder):
            os.mkdir(self.ownerFolder)
            os.mkdir(self.ownerFolder+"/localStorage")
            os.mkdir(self.ownerFolder+"/TPM")
        privateKeysFile = os.path.join(
            self.ownerFolder, "TPM", self.did+".key")
        print(privateKeysFile)
        self.publicKey = generateKeyPair(privateKeysFile)
        print("create owner: "+self.did)

        self.DID = {}
        self.DID["@context"] = [
            "https://www.w3id.org/did/v1"
        ]
        self.DID["id"] = self.did

        self.DID["publicKey"] = []
        publicKey = {}
        publicKey["id"] = self.publicKey
        publicKey["type"] = "RsaSignatureAuthentication2022"
        publicKey["owner"] = self.did
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

        didFile = os.path.join(self.ownerFolder, "localStorage", self.did+".json")
        blockChainFile = "../blockChain/dids.json"

        did = json.dumps(self.DID)
        with open(didFile, "w") as outfile:
            outfile.write(did)

        dids = "nothing"
        with open(blockChainFile, "r") as infile:
            temp = json.load(infile)
            temp[self.did] = self.DID
            dids = json.dumps(temp)
        with open(blockChainFile, "w") as outfile:
            outfile.write(dids)

        print("new item added")
