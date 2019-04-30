const credrequest = require("./credrequest.js")
const issuerkey = require("./issuerkey.js")
const util = require("./utils.js")


let AttributeNames = [ "Attr1", "Attr2", "Attr3", "Attr4", "Attr5" ]

let key = issuerkey.NewIssuerKey(AttributeNames);


let sk = util.RandModOrder(util.rng);
//let sk2 = RandModOrder(rng);

ni = util.RandModOrder(util.rng)

let m = credrequest.NewCredRequest(sk, util.BigToBytes(ni), key.Ipk)

util.LOG(m,"CredRequest")