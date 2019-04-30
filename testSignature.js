const credential = require("./credential.js")
const credrequest = require("./credrequest.js")
const issuerkey = require("./issuerkey.js")
const nym = require("./nymsignature.js")
const util = require("./utils.js")
const signature = require("./signature.js")




let AttributeNames = [ "Attr1", "Attr2", "Attr3", "Attr4", "Attr5" ]

let key = issuerkey.NewIssuerKey(AttributeNames);


let sk = util.RandModOrder(util.rng);
//let sk2 = RandModOrder(rng);

ni = util.RandModOrder(util.rng)

let m = credrequest.NewCredRequest(sk, util.BigToBytes(ni), key.Ipk)


// Set les valeurs des attributs qui seront signes ds le certificat
let attrs = new Array(AttributeNames.length)
for (i=0;i< AttributeNames.length;i++) {
    attrs[i] = new util.FP256BN.BIG(i)
}

let cred = credential.NewCredential(key, m, attrs )

credential.VerCred(cred,sk,key.Ipk)


let disclosure = [ 1, 0 ,0 ,0,0]
//let disclosure = [] 
let msg = Buffer.from("hello5")
msg2 = Buffer.from("hejjkjkllo5")
let rhindex= 4
let cri = null
let nn = nym.MakeNym(sk, key.Ipk)
sig = signature.NewSignature(cred, sk, nn.Nym, nn.RandNym, key.Ipk, disclosure, msg, rhindex, cri)
//console.log(JSON.stringify(sig));

// Là on teste les valeur des attribut.  Seul ceux qui on tles disclosre à 1
// seront verifiés
let attrsvalues = new Array(AttributeNames.length)
for (i=0;i< AttributeNames.length;i++) {
    attrsvalues[i] = new util.FP256BN.BIG(i)
}

signature.VerSignature(sig, disclosure, key.Ipk, msg, attrsvalues, 0, null, null)
console.log(key.Ipk)