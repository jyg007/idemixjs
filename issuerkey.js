const util = require("./utils.js");

const FP256BN = util.FP256BN
const GenG1 = util.GenG1
const FieldBytes = util.FieldBytes


//****************************************************************************************************************** */
//****************************************************************************************************************** */
//****************************************************************************************************************** */
function NewIssuerKey(AttributeNames) {
    let key = { Isk : "", Ipk : { HAttrs: [] , AttributeNames: [] , W:"", HRand: "" , BarG1: "",HSk: "" ,BarG2:"" }   };

    let attributeNamesMap = new Map();
    AttributeNames.forEach(
        (value) => {
            attributeNamesMap[value] = true
        }
    );

    let Isk = util.RandModOrder(util.rng);
    key.Isk = Isk;
    //console.log(FP256BN.BIG.prototype.toBytes(Isk));
    //console.log(Isk);
    
    //let a = new FP256BN.FP2(FP256BN.ROM_CURVE.CURVE_Pxa,FP256BN.ROM_CURVE.CURVE_Pxb);
    //let b = new FP256BN.FP2(FP256BN.ROM_CURVE.CURVE_Pya,FP256BN.ROM_CURVE.CURVE_Pyb);
    
    key.Ipk.AttributeNames = AttributeNames;
    let W = util.GenG2.mul(Isk);
    key.Ipk.W = W;
    
    // Essai sur un attribut
	key.Ipk.HAttrs = new Array(AttributeNames.length)
	for (i = 0; i < AttributeNames.length; i++) {
		key.Ipk.HAttrs[i] = GenG1.mul(util.RandModOrder(util.rng))
	}

    
    // generate base for the secret key
    let HSk = GenG1.mul(util.RandModOrder(util.rng));
    //console.log(HSk);
    key.Ipk.HSk = HSk;
    
    // generate base for the randomness
    let HRand = GenG1.mul(util.RandModOrder(util.rng));
    key.Ipk.HRand = HRand;
    
    let BarG1 = GenG1.mul(util.RandModOrder(util.rng));
    key.Ipk.BarG1 = BarG1;
    
    let BarG2 = BarG1.mul(Isk);
    key.Ipk.BarG2 = BarG2;
    
    let r = util.RandModOrder(util.rng)
    let t1 = util.GenG2.mul(r);
    let t2 = BarG1.mul(r);
    
    proofData = new ArrayBuffer(18*FieldBytes+3);
    let v = new Uint8Array(proofData);
    let index=0;
    index = util.appendBytesG2(proofData, index, t1);
    //console.log(v.toString());
    index = util.appendBytesG1(proofData, index, t2);
    //console.log(v.toString());
    index = util.appendBytesG2(proofData, index, util.GenG2);
    //console.log(v.toString());
    index = util.appendBytesG1(proofData, index, BarG1);
    index = util.appendBytesG2(proofData, index, W);
    index = util.appendBytesG1(proofData, index, BarG2);
    
    key.Ipk.ProofC = util.HashModOrder(v);
    key.Ipk.ProofS = util.Modadd(FP256BN.BIG.modmul(key.Ipk.ProofC,Isk,util.GroupOrder), r,util.GroupOrder);
    
    //console.log(proofS);
  //  key.Ipk.ProofS = new Uint8Array(FP256BN.BIG.MODBYTES);
   // proofS.toBytes(key.Ipk.ProofS);
    
    
    serializedIPk = Buffer.from(JSON.stringify(key.Ipk));
    key.Ipk.Hash = util.HashModOrder(serializedIPk);

    return key;
}


//****************************************************************************************************************** */
// Check checks that this issuer public key is valid, i.e.
// that all components are present and a ZK proofs verifies

function Check(IPk) {
    proofData = new ArrayBuffer(18*FieldBytes+3);
    let v = new Uint8Array(proofData);

    let t1= util.GenG2.mul(IPk.ProofS);
    t1.add(IPk.W.mul(FP256BN.BIG.modneg(IPk.ProofC, util.GroupOrder)));

    let t2 = IPk.BarG1.mul(IPk.ProofS);
    t2.add(IPk.BarG2.mul(FP256BN.BIG.modneg(IPk.ProofC, util.GroupOrder)));

    let index=0;
    index = util.appendBytesG2(proofData, index, t1);
    index = util.appendBytesG1(proofData, index, t2);
    index = util.appendBytesG2(proofData, index, util.GenG2);
    index = util.appendBytesG1(proofData, index, IPk.BarG1);
    index = util.appendBytesG2(proofData, index, IPk.W);
    index = util.appendBytesG1(proofData, index, IPk.BarG2);
    
 
    let c1 = JSON.stringify(IPk.ProofC);
    let c2 = JSON.stringify(util.HashModOrder(v));
    if (c1 != c2)  {
       throw Error("zero knowledge proof in public key invalid");
    } 
}


module.exports = {
    NewIssuerKey:NewIssuerKey,
    Check: Check,
}
