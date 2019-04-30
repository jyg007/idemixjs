const wbb = require("./weak-bb.js")

let k = wbb.WBBKeyGen();

let mg= Buffer.from("Hello");

//console.log(mg);
let sig = wbb.WBBSign(k.sk,mg);

let mg2=Buffer.from("Hellno");

//console.log(mg);

console.log(sig.toString());
console.log(wbb.WBBVerify(k.pk,sig,mg));
console.log(wbb.WBBVerify(k.pk,sig,mg2));