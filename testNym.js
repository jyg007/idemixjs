const nym = require("./nymsignature.js")
const util = require("./utils.js")
const issuerkey = require("./issuerkey.js")

let AttributeNames = [ "Attr1", "Attr2", "Attr3", "Attr4", "Attr5" ]


let key = issuerkey.NewIssuerKey(AttributeNames);


let sk = util.RandModOrder(util.rng);
//let sk2 = RandModOrder(rng);

let nn = nym.MakeNym(sk, key.Ipk);

//sig = NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, cri, rng)
let nymsig = nym.NewNymSignature(sk, nn.Nym, nn.RandNym, key.Ipk, Buffer.from("testing"))

console.log(nym.VerNym( nn.Nym, key.Ipk, Buffer.from("testing"), nymsig))

//let nymsig2 = NewNymSignature(sk2, nn.Nym, nn.RandNym, key.Ipk, Buffer.from("testing"), rng)
/*
console.log("Test Clé Privé différenteh")
console.log(VerNym( nn.Nym, key.Ipk, Buffer.from("testing"), nymsig2))
console.log(JSON.stringify(key.Ipk))
console.log(JSON.stringify(nn.Nym))
console.log(JSON.stringify(nn.Nym2))

*/