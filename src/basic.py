import random

############ implemention by TPM ############


def createRandomString():
    print("createRandomString")
    return str(random.randint(0, 99999999))


def createUniqueDID():
    print("createUniqueDID")
    return "did:"+createRandomString()


def generateKeyPair(privateKeysFile):
    print("generateKeyPair")
    publicKey = "#publicKey-1"
    privateKey = "#privateKey-1"

    # write private key into TPM
    with open(privateKeysFile, "w") as outfile:
        outfile.write(privateKey)

    return publicKey


def signVC(jsonFile, privateKey):
    print("signVC")
    return "signed_"+jsonFile + privateKey


def verifyVC(vcWithoutSignature, publicKey, signatureValue):
    print("verifyVC")
    return True


def storeVC(s):
    print("storeVC:"+s)


def getVC():
    s = "VC"
    print("getVC:"+s)
    return s
