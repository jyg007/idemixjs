
const credential = require("./credential.js")
const credrequest = require("./credrequest.js")
const issuerkey = require("./issuerkey.js")
const util = require("./utils.js")


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

util.LOG(cred,"cred");
credential.VerCred(cred,sk,key.Ipk)