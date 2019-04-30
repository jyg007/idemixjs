const issuerkey = require("./issuerkey.js")

let AttributeNames = [ "Attr1", "Attr2", "Attr3", "Attr4", "Attr5" ]

let key = issuerkey.NewIssuerKey(AttributeNames);
console.log(key.Ipk);
issuerkey.Check(key.Ipk);