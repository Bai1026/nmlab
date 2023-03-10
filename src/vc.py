import datetime
import json
import os
from basic import createRandomString, signVC

class VC_transfer:
    def __init__(self, issuer, verifier, holder, item):
        self.id = createRandomString()
        self.issuer = issuer
        self.verifier = verifier
        self.holder = holder
        self.item = item
        self.action = "Ownership_transfer"

        current_time = datetime.datetime.now()
        self.VC = {}
        self.VC["@context"] = [
            "https://www.w3id.org/VC/v1"
        ]
        self.VC["id"] = self.id
        self.VC["type"] = ["Credential"]
        self.VC["type"].append(self.action)
        self.VC["issuer"] = issuer
        self.VC["issued"] = "2010-01-01"

        self.VC["claim"] = {}
        self.VC["claim"]["holder"] = self.holder
        self.VC["claim"]["verifier"] = self.verifier
        self.VC["claim"]["item"] = self.item

        self.VC["revocation"] = {}
        self.VC["revocation"]["id"] = "http://example.gov/revocation/738"
        self.VC["revocation"]["type"] = "SimpleRevocationList2022"

        self.VC["signature"] = {}
        self.VC["signature"]["type"] = "LinkedDataSignature2022"
        self.VC["signature"]["created"] = "\""+str(current_time)+"\""
        self.VC["signature"]["creator"] = self.holder
        self.VC["signature"]["domain"] = "json-ld.org"
        self.VC["signature"]["type"] = "12345678"
        self.VC["signature"]["type"] = "LinkedDataSignature2022"
        vc = json.dumps(self.VC)

        ##### sign VC #####
        dataFolder = "../data"
        holderPrivateKey = os.path.join(dataFolder, self.holder, "TPM", self.holder+".key")
        self.VC["signature"]["signatureValue"] = signVC(vc, holderPrivateKey)

        ##### write VC into TPM #####
        vc = json.dumps(self.VC)
        vcFile = os.path.join(dataFolder, self.verifier, "TPM", "vc_"+self.item+".json") # stored in verifier's TPM
        with open(vcFile, "w") as outfile:
            outfile.write(vc)
        print("vc transfer from", holder, "to", verifier)

class VC_revoke:
    def __init__(self, issuer, holder, item):
        self.id = createRandomString()
        self.issuer = issuer
        self.verifier = "none"
        self.holder = holder
        self.item = item
        self.action = "Items_revocation"

        current_time = datetime.datetime.now()
        self.VC = {}
        self.VC["@context"] = [
            "https://www.w3id.org/VC/v1"
        ]
        self.VC["id"] = self.id
        self.VC["type"] = ["Credential"]
        self.VC["type"].append(self.action)
        self.VC["issuer"] = issuer
        self.VC["issued"] = "2010-01-01"

        self.VC["claim"] = {}
        self.VC["claim"]["holder"] = self.holder
        self.VC["claim"]["verifier"] = self.verifier
        self.VC["claim"]["item"] = self.item

        self.VC["revocation"] = {}
        self.VC["revocation"]["id"] = "http://example.gov/revocation/738"
        self.VC["revocation"]["type"] = "SimpleRevocationList2022"

        self.VC["signature"] = {}
        self.VC["signature"]["type"] = "LinkedDataSignature2022"
        self.VC["signature"]["created"] = "\""+str(current_time)+"\""
        self.VC["signature"]["creator"] = self.holder
        self.VC["signature"]["domain"] = "json-ld.org"
        self.VC["signature"]["type"] = "12345678"
        self.VC["signature"]["type"] = "LinkedDataSignature2022"
        vc = json.dumps(self.VC)

        ##### sign VC #####
        dataFolder = "../data"
        holderPrivateKey = os.path.join(dataFolder, self.holder, "TPM", self.holder+".key")
        self.VC["signature"]["signatureValue"] = signVC(vc, holderPrivateKey)

        ##### remove DID from TPM #####

        dataFolder = "../data"
        didFile = os.path.join(dataFolder, self.id, "localStorage", self.id+".json")
        os.remove(didFile)
        print("new transaction added")
