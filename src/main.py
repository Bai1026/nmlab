from item import Item
from owner import Owner
from vc import VC_transfer 
from vc import VC_revoke

##### DID initialization: everyone has a TPM to generate its DID #####
A_factory = "did:A_factory"
B_factory = "did:B_factory"
C_factory = "did:C_factory"
D_factory = "did:D_factory"
E_contractor = "did:E_contractor"
F_Army = "did:F_Army"
G_MinistryOfDefense = "did:G_MinistryOfDefense"
A = Owner(A_factory)
B = Owner(B_factory)
C = Owner(C_factory)
D = Owner(D_factory)
E = Owner(E_contractor)
F = Owner(F_Army)
G = Owner(G_MinistryOfDefense)


##### Step 1: create new items #####
barrel = Item(A.did) # 槍管
gunstock = Item(B.did) # 槍托
magazine = Item(C.did) # 彈匣
gun = Item(D.did) # 彈匣


##### Step 2-1: A transfer item to D #####
issuer = A.did
verifier = D.did
holder = A.did
item_did = barrel.id
action = "Ownership_transfer"
vc1 = VC_transfer(issuer, verifier, holder, item_did)

##### Step 2-2: B transfer item to D #####
issuer = B.did
verifier = D.did
holder = B.did
item_did = gunstock.id
action = "Ownership_transfer"
vc2 = VC_transfer(issuer, verifier, holder, item_did)

##### Step 2-3: C transfer item to D #####
issuer = C.did
verifier = D.did
holder = C.did
item_did = magazine.id
action = "Ownership_transfer"
vc3 = VC_transfer(issuer, verifier, holder, item_did)

##### Step 3: D transfer item to E #####
issuer = G.did
verifier = E.did
holder = D.did
item_did = gun.id
action = "Ownership_transfer"
vc4 = VC_transfer(issuer, verifier, holder, item_did)

##### Step 4: E transfer item to F #####
issuer = G.did
verifier = F.did
holder = E.did
item_did = gun.id
action = "Ownership_transfer"
vc5 = VC_transfer(issuer, verifier, holder, item_did)

# ##### Step 5: F revoke item #####
# issuer = G.did
# verifier = G.did
# holder = E.did
# item_did = gun.id
# action = "Revocation"
# vc6 = VC_revoke(issuer, holder, item_did)