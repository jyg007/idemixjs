var fs = require('fs');
var c = require('./js/ctx.js')

//var rng=new ctx.RAND();
var bu= new ArrayBuffer(512);

var buffer = Buffer.from(bu);
let fd=fs.openSync('/dev/urandom','r');
let n = fs.readSync(fd, buffer, 0, 512, 0);
fs.closeSync(fd);

const ctx =  new c.CTX('ED25519');

var rng=new ctx.RAND();

rng.clean();
rng.seed(1512,buffer);

var S0=[];
var W0=[];

var S1=[];
var W1=[];

ctx.ECDH.KEY_PAIR_GENERATE(rng,S0,W0); 
ctx.ECDH.KEY_PAIR_GENERATE(rng,S1,W1); 

console.log("User0 secret and pub key")
console.log(ctx.ECDH.bytestostring(S0));
console.log(ctx.ECDH.bytestostring(W0));

var Z0=[];
var Z1=[];
var RAW=[];
var SALT=[];
var P1=[];
var P2=[];
var V=[];
var M=[];
var T=new Array(12);

ctx.ECDH.ECPSVDP_DH(S0,W1,Z0);
ctx.ECDH.ECPSVDP_DH(S1,W0,Z1);

console.log("\nShared Key:")

console.log(ctx.ECDH.bytestostring(Z0));
console.log(ctx.ECDH.bytestostring(Z1));