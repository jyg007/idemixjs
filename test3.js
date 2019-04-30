let fs = require('fs');
let c = require('./js/ctx.js')

const crypto = require('crypto');


//let rng=new ctx.RAND();
let bu= new ArrayBuffer(512);

let buffer = Buffer.from(bu);
let fd=fs.openSync('/dev/urandom','r');
let n = fs.readSync(fd, buffer, 0, 512, 0);
fs.closeSync(fd);

const FP256BN =  new c.CTX('FP256BN');

let rng=new FP256BN.RAND();

rng.clean();
rng.seed(1512,buffer);

let S0=[];
let W0=[];

FP256BN.ECDH.KEY_PAIR_GENERATE(rng,S0,W0); 

//RandModOrder  

function Mul2(a,b,c,d) {
    a = a.mul(b)
    c = c.mul(d)
    a.add(c)
    return a
}

function LOG(a,msg) {
    console.log(JSON.stringify(a)," ",msg,"\n")
}

/************************************************************************************* */
/************************************************************************************* */
function RandModOrder(rng) {
    let q = new FP256BN.BIG(0);
    q.rcopy(FP256BN.ROM_CURVE.CURVE_Order);
    return FP256BN.BIG.randomnum(q,rng);
}

/************************************************************************************* */
/************************************************************************************* */
let GenG2 = new FP256BN.ECP2.generator();
let GenG1 = new FP256BN.ECP.generator();
let GenGT = FP256BN.PAIR.fexp(FP256BN.PAIR.ate(GenG2, GenG1));
let GroupOrder = new FP256BN.BIG(0);
GroupOrder.rcopy(FP256BN.ROM_CURVE.CURVE_Order);
const FieldBytes = FP256BN.BIG.MODBYTES;

const credRequestLabel = "credRequest";
// signLabel is the label used in zero-knowledge proof (ZKP) to identify that this ZKP is a signature of knowledge
const signLabel = "sign"

/************************************************************************************* */
/************************************************************************************* */
function appendBytes(data , index , bytesToAdd )  {
    data.set(bytesToAdd,index);
	return index + bytesToAdd.length
}

/************************************************************************************* */
/************************************************************************************* */
function appendBytesG1(data, index, E ) {
    let length = 2*FieldBytes + 1;
    let datab = new Uint8Array(data, index,length);  
	E.toBytes(datab, false)
	return index + length;
}

/************************************************************************************* */
/************************************************************************************* */
function appendBytesBig(data , index , B )  {
    let length = FieldBytes
    let datab = new Uint8Array(data, index, length); 
	B.toBytes(datab)
	return index + length
}
/************************************************************************************* */
/************************************************************************************* */

function appendBytesString(data , index , s )  {
    let bytes = Buffer.from(s); 
	data.set(bytes,index);
	return index + bytes.length;
}

/************************************************************************************* */
/************************************************************************************* */
function appendBytesG2(data, index, E )  {
    let length = 4 * FieldBytes;
    let datab = new Uint8Array(data, index, length);  
	E.toBytes(datab)
	return index + length;
}

/************************************************************************************* */
/************************************************************************************* */
function Modadd(a, b, m) {
    let c;
    c = a.plus(b);
    c.mod(m);
	return c;
}


/************************************************************************************* */
/************************************************************************************* */
// Modsub takes input BIGs a, b, m and returns a-b modulo m
function Modsub(a, b, m )  {
    return Modadd(a, FP256BN.BIG.modneg(b, m), m)
}


/************************************************************************************* */
/************************************************************************************* */
function HashModOrder(data) {
    let hash = crypto.createHash('sha256');
    hash.update(data);
    let o = hash.digest('binary');

    let digestBig = FP256BN.BIG.fromBytes(Buffer.from(o));
    digestBig.mod(GroupOrder);
	return digestBig;
}

/************************************************************************************* */
/************************************************************************************* */
function BigToBytes(big) {
	let ret = new Uint8Array(FieldBytes);
	big.toBytes(ret)
	return ret
}



//****************************************************************************************************************** */
//****************************************************************************************************************** */
//****************************************************************************************************************** */
function NewIssuerKey(AttributeNames, rng) {
    let key = { Isk : "", Ipk : { HAttrs: [] , AttributeNames: [] , W:"", HRand: "" , BarG1: "",HSk: "" ,BarG2:"" }   };

    let attributeNamesMap = new Map();
    AttributeNames.forEach(
        (value) => {
            attributeNamesMap[value] = true
        }
    );

    let Isk = RandModOrder(rng);
    key.Isk = Isk;
    //console.log(FP256BN.BIG.prototype.toBytes(Isk));
    //console.log(Isk);
    
    //let a = new FP256BN.FP2(FP256BN.ROM_CURVE.CURVE_Pxa,FP256BN.ROM_CURVE.CURVE_Pxb);
    //let b = new FP256BN.FP2(FP256BN.ROM_CURVE.CURVE_Pya,FP256BN.ROM_CURVE.CURVE_Pyb);
    
    key.Ipk.AttributeNames = AttributeNames;
    let W = GenG2.mul(Isk);
    key.Ipk.W = W;
    
    // Essai sur un attribut
	key.Ipk.HAttrs = new Array(AttributeNames.length)
	for (i = 0; i < AttributeNames.length; i++) {
		key.Ipk.HAttrs[i] = GenG1.mul(RandModOrder(rng))
	}

    
    // generate base for the secret key
    let HSk = GenG1.mul(RandModOrder(rng));
    //console.log(HSk);
    key.Ipk.HSk = HSk;
    
    // generate base for the randomness
    let HRand = GenG1.mul(RandModOrder(rng));
    key.Ipk.HRand = HRand;
    
    let BarG1 = GenG1.mul(RandModOrder(rng));
    key.Ipk.BarG1 = BarG1;
    
    let BarG2 = BarG1.mul(Isk);
    key.Ipk.BarG2 = BarG2;
    
    let r = RandModOrder(rng)
    let t1 = GenG2.mul(r);
    let t2 = BarG1.mul(r);
    
    proofData = new ArrayBuffer(18*FieldBytes+3);
    let v = new Uint8Array(proofData);
    let index=0;
    index = appendBytesG2(proofData, index, t1);
    //console.log(v.toString());
    index = appendBytesG1(proofData, index, t2);
    //console.log(v.toString());
    index = appendBytesG2(proofData, index, GenG2);
    //console.log(v.toString());
    index = appendBytesG1(proofData, index, BarG1);
    index = appendBytesG2(proofData, index, W);
    index = appendBytesG1(proofData, index, BarG2);
    
    key.Ipk.ProofC = HashModOrder(v);
    key.Ipk.ProofS = Modadd(FP256BN.BIG.modmul(key.Ipk.ProofC,Isk,GroupOrder), r,GroupOrder);
    
    //console.log(proofS);
  //  key.Ipk.ProofS = new Uint8Array(FP256BN.BIG.MODBYTES);
   // proofS.toBytes(key.Ipk.ProofS);
    
    
    serializedIPk = Buffer.from(JSON.stringify(key.Ipk));
    key.Ipk.Hash = HashModOrder(serializedIPk);

    return key;
}


/************************************************************************************* */
function WBBKeyGen(rng) {
    let k =  { pk : "", sk : "" };
    k.sk = RandModOrder(rng);
    k.pk = GenG2.mul(k.sk);
    return k;    
}

/************************************************************************************* */
function WBBSign(sk, m) {
    let exp = Modadd(sk,m,GroupOrder);
    exp.invmodp(GroupOrder);
    return GenG1.mul(exp);
}

/************************************************************************************* */
function WBBVerify(pk, sig, m) {
    let p = new FP256BN.ECP2();
    p.copy(pk);
    p.add(GenG2.mul(m));
    p.affine();
    let o=FP256BN.PAIR.fexp(FP256BN.PAIR.ate(p,sig));
    return GenGT.equals(o);
}

//****************************************************************************************************************** */
// Check checks that this issuer public key is valid, i.e.
// that all components are present and a ZK proofs verifies

function Check(IPk) {
    proofData = new ArrayBuffer(18*FieldBytes+3);
    let v = new Uint8Array(proofData);

    let t1= GenG2.mul(IPk.ProofS);
    t1.add(IPk.W.mul(FP256BN.BIG.modneg(IPk.ProofC, GroupOrder)));

    let t2 = IPk.BarG1.mul(IPk.ProofS);
    t2.add(IPk.BarG2.mul(FP256BN.BIG.modneg(IPk.ProofC, GroupOrder)));

    let index=0;
    index = appendBytesG2(proofData, index, t1);
    index = appendBytesG1(proofData, index, t2);
    index = appendBytesG2(proofData, index, GenG2);
    index = appendBytesG1(proofData, index, IPk.BarG1);
    index = appendBytesG2(proofData, index, IPk.W);
    index = appendBytesG1(proofData, index, IPk.BarG2);
    
 
    let c1 = JSON.stringify(IPk.ProofC);
    let c2 = JSON.stringify(HashModOrder(v));
    if (c1 != c2)  {
       throw Error("zero knowledge proof in public key invalid");
    } 
}







//****************************************************************************************************************** */
function MakeNym(sk , IPk , rng ) {
    let k = { Nym : "", RandNym :""};
	// Construct a commitment to the sk
	// Nym = h_{sk}^sk \cdot h_r^r
	k.RandNym = RandModOrder(rng)
	k.Nym = IPk.HSk.mul2(sk, IPk.HRand, k.RandNym)
	return k
}

//****************************************************************************************************************** */
//Sign produces a signature over the passed digest. 
//It takes in input, the user secret key (sk), 
//the pseudonym public key (Nym) and secret key (RNym), 
//and the issuer public key (ipk).

function NewNymSignature(sk, Nym , RNym , ipk , msg , rng )  {
	let Nonce = RandModOrder(rng)

	let HRand = ipk.HRand;
	let HSk = ipk.HSk;

	// The rest of this function constructs the non-interactive zero knowledge proof proving that
	// the signer 'owns' this pseudonym, i.e., it knows the secret key and randomness on which it is based.
	// Recall that (Nym,RNym) is the output of MakeNym. Therefore, Nym = h_{sk}^sk \cdot h_r^r

	// Sample the randomness needed for the proof
	let rSk = RandModOrder(rng)
	let rRNym = RandModOrder(rng)

	// Step 1: First message (t-values)
	let t = HSk.mul2(rSk, HRand, rRNym) // t = h_{sk}^{r_sk} \cdot h_r^{r_{RNym}

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData will hold the data being hashed, it consists of:
	// - the signature label
	// - 2 elements of G1 each taking 2*FieldBytes+1 bytes
	// - one bigint (hash of the issuer public key) of length FieldBytes
	// - disclosed attributes
	// - message being signed
    let proofData = new ArrayBuffer(signLabel.length+2*(2*FieldBytes+1)+FieldBytes+msg.length);
    let v = new Uint8Array(proofData);

    let index = 0

    index = appendBytesString(v, index, signLabel)
    index = appendBytesG1(proofData, index, t)
    index = appendBytesG1(proofData, index, Nym)
    v.set(BigToBytes(ipk.Hash),index);
    index = index + FieldBytes
    v.set(Buffer.from(msg),index);
    let c = HashModOrder(v);


    // combine the previous hash and the nonce and hash again to compute the final Fiat-Shamir value 'ProofC'
    index = 0
    let proofData2 = new ArrayBuffer(2*FieldBytes);
    let v2 = new Uint8Array(proofData2);

	index = appendBytesBig(proofData2, index, c)
	index = appendBytesBig(proofData2, index, Nonce)
    ProofC = HashModOrder(v2)

    // Step 3: reply to the challenge message (s-values)
	let ProofSSk = Modadd(rSk, FP256BN.BIG.modmul(ProofC, sk, GroupOrder), GroupOrder)       // s_{sk} = r_{sk} + C \cdot sk
    let ProofSRNym = Modadd(rRNym, FP256BN.BIG.modmul(ProofC, RNym, GroupOrder), GroupOrder) // s_{RNym} = r_{RNym} + C \cdot RNym
    
    return {
		ProofC:     ProofC,
		ProofSSk:   ProofSSk,
		ProofSRNym: ProofSRNym,
        Nonce:      Nonce
    }
};

//****************************************************************************************************************** */
function VerNym( nym , ipk , msg ,sig)  {
	let ProofC = sig.ProofC;
	let ProofSSk = sig.ProofSSk;
	let ProofSRNym = sig.ProofSRNym;
    let Nonce = sig.Nonce;
    
	let HRand = ipk.HRand;
	let HSk = ipk.HSk;

	// Verify Proof

	// Recompute t-values using s-values
	let t = HSk.mul2(ProofSSk, HRand, ProofSRNym);
	t.sub(nym.mul(ProofC)) // t = h_{sk}^{s_{sk} \ cdot h_r^{s_{RNym}

	// Recompute challenge
    let proofData = new ArrayBuffer(signLabel.length+2*(2*FieldBytes+1)+FieldBytes+msg.length);
    let v = new Uint8Array(proofData);
	let index = 0
	index = appendBytesString(v, index, signLabel)
	index = appendBytesG1(proofData, index, t)
    index = appendBytesG1(proofData, index, nym)
    
    //  copy(proofData[index:], ipk.Hash)
    v.set(BigToBytes(ipk.Hash),index);
    index = index + FieldBytes
    v.set(Buffer.from(msg),index);
   // copy(proofData[index:], msg)
    
	c = HashModOrder(v)
    index = 0
    let proofData2 = new ArrayBuffer(2*FieldBytes);
    let v2 = new Uint8Array(proofData2);

	index = appendBytesBig(proofData2, index, c)
	index = appendBytesBig(proofData2, index, Nonce)

    let c1 = JSON.stringify(ProofC);
    let c2 = JSON.stringify(HashModOrder(v2))


    if (c1 != c2)  {
        return false;
        //throw  Error("pseudonym signature invalid: zero-knowledge proof is invalid")
    } 
    else return true;

}









//****************************************************************************************************************** */
//****************************************************************************************************************** */
// Credential issuance is an interactive protocol between a user and an issuer
// The issuer takes its secret and public keys and user attribute values as input
// The user takes the issuer public key and user secret as input
// The issuance protocol consists of the following steps:
// 1) The issuer sends a random nonce to the user
// 2) The user creates a Credential Request using the public key of the issuer, user secret, and the nonce as input
//    The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof
//     of knowledge of the user secret key
//    The user sends the credential request to the issuer
// 3) The issuer verifies the credential request by verifying the zero-knowledge proof
//    If the request is valid, the issuer issues a credential to the user by signing the commitment to the secret key
//    together with the attribute values and sends the credential back to the user
// 4) The user verifies the issuer's signature and stores the credential that consists of
//    the signature value, a randomness used to create the signature, the user secret, and the attribute values


// NewCredRequest creates a new Credential Request, the first message of the interactive credential issuance protocol
// (from user to issuer)
function NewCredRequest(sk , IssuerNonce , ipk , rng )  {
	// Set Nym as h_{sk}^{sk}
	let HSk = ipk.HSk
	let Nym = HSk.mul(sk)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key

	// Sample the randomness needed for the proof
	let rSk = RandModOrder(rng)

	// Step 1: First message (t-values)
	let t = HSk.mul(rSk) // t = h_{sk}^{r_{sk}}, cover Nym

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData is the data being hashed, it consists of:
	// the credential request label
	// 3 elements of G1 each taking 2*FieldBytes+1 bytes
	// hash of the issuer public key of length FieldBytes
    // issuer nonce of length FieldBytes
  
    let proofData = new ArrayBuffer(credRequestLabel.length+3*(2*FieldBytes+1)+2*FieldBytes);
    let v = new Uint8Array(proofData);
	let index = 0

	index = appendBytesString(v, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
    index = appendBytes(v, index, IssuerNonce)
    v.set(BigToBytes(ipk.Hash),index)
	let proofC = HashModOrder(v)

	// Step 3: reply to the challenge message (s-values)
	let proofS = Modadd(FP256BN.BIG.modmul(proofC, sk, GroupOrder), rSk, GroupOrder) // s = r_{sk} + C \cdot sk

	// Done
	return {
		Nym:         Nym,
		IssuerNonce: IssuerNonce,
		ProofC:      proofC,
        ProofS:      proofS
    }
}



// Check cryptographically verifies the credential request
function  CheckCredReq(CredRequest, ipk )  {
	let Nym = CredRequest.Nym
	let IssuerNonce = CredRequest.IssuerNonce
	let ProofC = CredRequest.ProofC
	let ProofS = CredRequest.ProofS

	let HSk = ipk.HSk
/*
	if Nym == nil || IssuerNonce == nil || ProofC == nil || ProofS == nil {
		return errors.Errorf("one of the proof values is undefined")
	}
*/
    // Verify Proof


	// Recompute t-values using s-values
	let t = HSk.mul(ProofS)
	t.sub(Nym.mul(ProofC)) // t = h_{sk}^s / Nym^C

	// Recompute challenge
    let proofData = new ArrayBuffer( credRequestLabel.length+3*(2*FieldBytes+1)+2*FieldBytes)    
    let v = new Uint8Array(proofData);
	let index = 0
	index = appendBytesString(v, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
	index = appendBytes(v, index, IssuerNonce)
    v.set(BigToBytes(ipk.Hash),index)

	if (JSON.stringify(ProofC) != JSON.stringify(HashModOrder(v))) {
		throw error("zero knowledge proof is invalid")
	}

}




//****************************************************************************************************************** */
//****************************************************************************************************************** */
function NewCredential(key , m , attrs , rng )  {

	CheckCredReq(m,key.Ipk)

	if (attrs.length != key.Ipk.AttributeNames.length) {
		throw new Error("incorrect number of attribute values passed")
	}

	// Place a BBS+ signature on the user key and the attribute values
	// (For BBS+, see e.g. "Constant-Size Dynamic k-TAA" by Man Ho Au, Willy Susilo, Yi Mu)
	// or http://eprint.iacr.org/2016/663.pdf, Sec. 4.3.

	// For a credential, a BBS+ signature consists of the following three elements:
	// 1. E, random value in the proper group
	// 2. S, random value in the proper group
	// 3. A as B^Exp where B=g_1 \cdot h_r^s \cdot h_sk^sk \cdot \prod_{i=1}^L h_i^{m_i} and Exp = \frac{1}{e+x}
	// Notice that:
	// h_r is h_0 in http://eprint.iacr.org/2016/663.pdf, Sec. 4.3.

	// Pick randomness E and S
	let E = RandModOrder(rng)
	let S = RandModOrder(rng)

	// Set B as g_1 \cdot h_r^s \cdot h_sk^sk \cdot \prod_{i=1}^L h_i^{m_i} and Exp = \frac{1}{e+x}
	let B = new FP256BN.ECP();
	B.copy(GenG1) // g_1
	let Nym = m.Nym
    B.add(Nym)
    // in this case, recall Nym=h_sk^sk
	B.add(key.Ipk.HRand.mul(S)) // h_r^s

	// Append attributes
	// Use Mul2 instead of Mul as much as possible for efficiency reasones
	for (i = 0; i < Math.floor(attrs.length/2); i++) {
		B.add(
			// Add two attributes in one shot
			key.Ipk.HAttrs[2*i].mul2(
				attrs[2*i],
				key.Ipk.HAttrs[2*i+1],
				attrs[2*i+1]
			)
		)
    }
    
	// Check for residue in case len(attrs)%2 is odd
	if (attrs.length % 2 != 0 ){
		B.add(key.Ipk.HAttrs[attrs.length-1].mul(attrs[attrs.length-1]))
	}

	// Set Exp as \frac{1}{e+x}
	let Exp = Modadd(key.Isk, E, GroupOrder)
	Exp.invmodp(GroupOrder)
	// Finalise A as B^Exp
   // let A = B.mul(Exp)
    let A  = new FP256BN.ECP()
    A.copy(B)
    A=A.mul(Exp)
	// The signature is now generated.

	// Notice that here we release also B, this does not harm security cause
	// it can be compute publicly from the BBS+ signature itself.
    let CredAttrs = new Array(attrs.length)
    for (i=0; i<attrs.length; i++) {
        CredAttrs[i] = attrs[i]
    }

	return  {
		A:     A,
		B:     B,
		E:     E,
		S:     S,
		Attrs: CredAttrs}
}


//****************************************************************************************************************** */
//****************************************************************************************************************** */
// Ver cryptographically verifies the credential by verifying the signature
// on the attribute values and user's secret key
function VerCred(cred, sk , ipk )  {
	// Validate Input

	// - parse the credential
	let A = cred.A
	let B = cred.B
	let E = cred.E
	let S = cred.S

	// - verify that all attribute values are present
	for (i = 0; i < cred.Attrs.length; i++) {
		if (cred.Attrs[i] == null) {
			//throw Error("credential has no value for attribute %s", ipk.AttributeNames[i])
		}
	}

	// - verify cryptographic signature on the attributes and the user secret key
	let BPrime = new FP256BN.ECP()
    BPrime.copy(GenG1)
    //BPrime.add(key.Ipk.HSk.mul(sk))
   // BPrime.add(key.Ipk.HRand.mul(S))
    //BPrime.add(Mul2(ipk.HSk,sk,ipk.HRand,S))
    BPrime.add(ipk.HSk.mul2(sk, ipk.HRand, S))
    
	// Append attributes
	// Use Mul2 instead of Mul as much as possible for efficiency reasones
	for (i = 0; i < Math.floor(cred.Attrs.length/2); i++) {
		BPrime.add(
			    ipk.HAttrs[2*i].mul2(
				cred.Attrs[2*i],
				ipk.HAttrs[2*i+1],
				cred.Attrs[2*i+1]
			)
		)
    }
    
	// Check for residue in case len(attrs)%2 is odd
	if (cred.Attrs.length % 2 != 0 ){
		BPrime.add(key.Ipk.HAttrs[cred.Attrs.length-1].mul(cred.Attrs[cred.Attrs.length-1]))
	}


    if (!B.equals(BPrime)) {
        throw Error("b-value from credential does not match the attribute values")
    }


	// Verify BBS+ signature. Namely: e(w \cdot g_2^e, A) =? e(g_2, B)
	let a = GenG2.mul(E)
	a.add(ipk.W)
	a.affine()

	let left = FP256BN.PAIR.fexp(FP256BN.PAIR.ate(a, A))
    let right = FP256BN.PAIR.fexp(FP256BN.PAIR.ate(GenG2, B))
    
    if (!left.equals(right)) {
        console.log(JSON.stringify(left));
        console.log(JSON.stringify(right));
        throw Error("credential is not cryptographically valid")
    }



}





//****************************************************************************************************************** */
//****************************************************************************************************************** */

// A signature that is produced using an Identity Mixer credential is a so-called signature of knowledge
// (for details see C.P.Schnorr "Efficient Identification and Signatures for Smart Cards")
// An Identity Mixer signature is a signature of knowledge that signs a message and proves (in zero-knowledge)
// the knowledge of the user secret (and possibly attributes) signed inside a credential
// that was issued by a certain issuer (referred to with the issuer public key)
// The signature is verified using the message being signed and the public key of the issuer
// Some of the attributes from the credential can be selectvely disclosed or different statements can be proven about
// credential atrributes without diclosing them in the clear
// The difference between a standard signature using X.509 certificates and an Identity Mixer signature is
// the advanced privacy features provided by Identity Mixer (due to zero-knowledge proofs):
//  - Unlinkability of the signatures produced with the same credential
//  - Selective attribute disclosure and predicates over attributes

// Make a slice of all the attribute indices that will not be disclosed

function hiddenIndices(Disclosure) {
    HiddenIndices = new Array(0)
    for (let i=0; i< Disclosure.length; i++) {
        if (Disclosure[i] == 0) {
            HiddenIndices.push(i);
        }
    }

	return HiddenIndices
}


//****************************************************************************************************************** */
//****************************************************************************************************************** */
// NewSignature creates a new idemix signature (Schnorr-type signature)
// The []byte Disclosure steers which attributes are disclosed:
// if Disclosure[i] == 0 then attribute i remains hidden and otherwise it is disclosed.
// We require the revocation handle to remain undisclosed (i.e., Disclosure[rhIndex] == 0).
// We use the zero-knowledge proof by http://eprint.iacr.org/2016/663.pdf, Sec. 4.5 to prove knowledge of a BBS+ signature
function NewSignature(cred , sk , Nym , RNym , ipk , Disclosure , msg , rhIndex , cri , rng ) {
    
    /*
    // Validate inputs
	if cred == nil || sk == nil || Nym == nil || RNym == nil || ipk == nil || rng == nil || cri == nil {
		return nil, errors.Errorf("cannot create idemix signature: received nil input")
	}

	if rhIndex < 0 || rhIndex >= len(ipk.AttributeNames) || len(Disclosure) != len(ipk.AttributeNames) {
		return nil, errors.Errorf("cannot create idemix signature: received invalid input")
	}

	if cri.RevocationAlg != int32(ALG_NO_REVOCATION) && Disclosure[rhIndex] == 1 {
		return nil, errors.Errorf("Attribute %d is disclosed but also used as revocation handle attribute, which should remain hidden.", rhIndex)
	}
*/

	// locate the indices of the attributes to hide and sample randomness for them
	HiddenIndices = hiddenIndices(Disclosure)

	// Generate required randomness r_1, r_2
	let r1 = RandModOrder(rng)
	let r2 = RandModOrder(rng)
	// Set r_3 as \frac{1}{r_1}
    let r3 = new FP256BN.BIG(r1)

	r3.invmodp(GroupOrder)

	// Sample a nonce
	let Nonce = RandModOrder(rng)

	// Parse credential
	let A = cred.A
	let B = cred.B
    let E = cred.E
    let S = cred.S

	// Randomize credential

	// Compute A' as A^{r_!}
	let APrime = FP256BN.PAIR.G1mul(A, r1)

	// Compute ABar as A'^{-e} b^{r1}
    let ABar = FP256BN.PAIR.G1mul(B, r1)
	ABar.sub(FP256BN.PAIR.G1mul(APrime, E))

	// Compute B' as b^{r1} / h_r^{r2}, where h_r is h_r
	let BPrime = FP256BN.PAIR.G1mul(B, r1)
	let HRand = ipk.HRand
	// Parse h_{sk} from ipk
	let HSk = ipk.HSk

	BPrime.sub(FP256BN.PAIR.G1mul(HRand, r2))

	// Compute s' as s - r_2 \cdot r_3
	let sPrime = Modsub(S, FP256BN.BIG.modmul(r2, r3, GroupOrder), GroupOrder)

	// The rest of this function constructs the non-interactive zero knowledge proof
	// that links the signature, the non-disclosed attributes and the nym.

	// Sample the randomness used to compute the commitment values (aka t-values) for the ZKP
	let rSk = RandModOrder(rng)
	let re = RandModOrder(rng)
	let rR2 = RandModOrder(rng)
	let rR3 = RandModOrder(rng)
	let rSPrime = RandModOrder(rng)
	let rRNym = RandModOrder(rng)

    let rAttrs = new Array(HiddenIndices.length)
    HiddenIndices.forEach(
        (value,i) => {
            rAttrs[i] = RandModOrder(rng)
        }
    )

/*
	// First compute the non-revocation proof.
	// The challenge of the ZKP needs to depend on it, as well.
	prover, err = getNonRevocationProver(RevocationAlgorithm(cri.RevocationAlg))
	if err != nil {
		return nil, err
	}
	nonRevokedProofHashData, err = prover.getFSContribution(
		FP256BN.FromBytes(cred.Attrs[rhIndex]),
		rAttrs[sort.SearchInts(HiddenIndices, rhIndex)],
		cri,
		rng,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute non-revoked proof")
	}
*/
	// Step 1: First message (t-values)

	// t1 is related to knowledge of the credential (recall, it is a BBS+ signature)
    let t1 = APrime.mul2(re, HRand, rR2) // A'^{r_E} . h_r^{r_{r2}}

	// t2: is related to knowledge of the non-disclosed attributes that signed  in (A,B,S,E)
	let t2 = FP256BN.PAIR.G1mul(HRand, rSPrime) // h_r^{r_{s'}}
    t2.add(BPrime.mul2(rR3, HSk, rSk))  // B'^{r_{r3}} \cdot h_{sk}^{r_{sk}}

     for (i = 0; i < Math.floor(HiddenIndices.length/2); i++){
		t2.add(
			// \cdot h_{2 \cdot i}^{r_{attrs,i}
			ipk.HAttrs[HiddenIndices[2*i]].mul2(
				rAttrs[2*i],
				ipk.HAttrs[HiddenIndices[2*i+1]],
				rAttrs[2*i+1],
			),
		)
	}
	if (HiddenIndices.length % 2 != 0 ){
		t2.add(FP256BN.PAIR.G1mul(ipk.HAttrs[HiddenIndices[HiddenIndices.length-1]], rAttrs[HiddenIndices.length-1]))
	}

	// t3 is related to the knowledge of the secrets behind the pseudonym, which is also signed in (A,B,S,E)
   	let t3 = HSk.mul2(rSk, HRand, rRNym) // h_{sk}^{r_{sk}} \cdot h_r^{r_{rnym}}
    //let t3 = Mul2(HSk,rSk, HRand, rRNym)

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.

	// Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData is the data being hashed, it consists of:
	// the signature label
	// 7 elements of G1 each taking 2*FieldBytes+1 bytes
    // one bigint (hash of the issuer public key) of length FieldBytes
    


	// disclosed attributes
	// message being signed
	// the amount of bytes needed for the nonrevocation proof
	//let proofData  = new ArrayBuffer( signLabel.lenght+7*(2*FieldBytes+1)+FieldBytes+Disclosure.length+msg.length+ProofBytes[RevocationAlgorithm(cri.RevocationAlg)])
	let proofData  = new ArrayBuffer( signLabel.length+7*(2*FieldBytes+1)+FieldBytes+Disclosure.length+msg.length)
    let v = new Uint8Array(proofData);
    let index = 0
	index = appendBytesString(v, index, signLabel)
    index = appendBytesG1(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG1(proofData, index, t3)
	index = appendBytesG1(proofData, index, APrime)
	index = appendBytesG1(proofData, index, ABar)
	index = appendBytesG1(proofData, index, BPrime)
	index = appendBytesG1(proofData, index, Nym)
    //index = appendBytes(proofData, index, nonRevokedProofHashData)
    v.set(BigToBytes(ipk.Hash),index);
	index = index + FieldBytes
    v.set(Buffer.from(Disclosure),index);
	index = index + Disclosure.length
    v.set(msg,index);
	let c = HashModOrder(v)

	// add the previous hash and the nonce and hash again to compute a second hash (C value)  
    index = 0
    proofData = proofData.slice(0,2*FieldBytes);
    let v2 = new Uint8Array(proofData);

	index = appendBytesBig(proofData, index, c)
	index = appendBytesBig(proofData, index, Nonce)

    ProofC = HashModOrder(v2)

    // Step 3: reply to the challenge message (s-values)
    ProofSSk = Modadd(rSk, FP256BN.BIG.modmul(ProofC, sk, GroupOrder), GroupOrder)             // s_sk = rSK + C . sk

    ProofSE = Modsub(re, FP256BN.BIG.modmul(ProofC, E, GroupOrder), GroupOrder)                // s_e = re + C . E
    ProofSR2 = Modadd(rR2, FP256BN.BIG.modmul(ProofC, r2, GroupOrder), GroupOrder)             // s_r2 = rR2 + C . r2


	let ProofSR3 = Modsub(rR3, FP256BN.BIG.modmul(ProofC, r3, GroupOrder), GroupOrder)             // s_r3 = rR3 + C \cdot r3
	let ProofSSPrime = Modadd(rSPrime, FP256BN.BIG.modmul(ProofC, sPrime, GroupOrder), GroupOrder) // s_S' = rSPrime + C \cdot sPrime
	let ProofSRNym = Modadd(rRNym, FP256BN.BIG.modmul(ProofC, RNym, GroupOrder), GroupOrder)       // s_RNym = rRNym + C \cdot RNym
    let ProofSAttrs = new Array(HiddenIndices.length)


    /*
	for i, j = range HiddenIndices {
		ProofSAttrs[i] = BigToBytes(
			// s_attrsi = rAttrsi + C \cdot cred.Attrs[j]
			Modadd(rAttrs[i], FP256BN.Modmul(ProofC, cred.Attrs[j], GroupOrder), GroupOrder),
		)
    }*/

    HiddenIndices.forEach(
        (j,i) => {
            // s_attrsi = rAttrsi + C \cdot cred.Attrs[j]
            ProofSAttrs[i] = Modadd(rAttrs[i], FP256BN.BIG.modmul(ProofC, cred.Attrs[j], GroupOrder), GroupOrder);  
        }
    )
    // Compute the revocation part
    /*
	nonRevokedProof, err = prover.getNonRevokedProof(ProofC)
	if err != nil {
		return nil, err
	}
*/

	// We are done. Return signature
	return {
			APrime:             APrime,
			ABar:               ABar,
			BPrime:             BPrime,
			ProofC:             ProofC,
			ProofSSk:           ProofSSk,
			ProofSE:            ProofSE,
			ProofSR2:           ProofSR2,
			ProofSR3:           ProofSR3,
			ProofSSPrime:       ProofSSPrime,
			ProofSAttrs:        ProofSAttrs,
			Nonce:              Nonce,
			Nym:                Nym,
			ProofSRNym:         ProofSRNym,
	//		RevocationEpochPk:  cri.EpochPk,
	//		RevocationPkSig:    cri.EpochPkSig,
	//		Epoch:              cri.Epoch,
    //      NonRevocationProof: nonRevokedProof
    }
}


//******************************************************************************************************************************************* */
//******************************************************************************************************************************************* */
// Ver verifies an idemix signature
// Disclosure steers which attributes it expects to be disclosed
// attributeValues contains the desired attribute values.
// This function will check that if attribute i is disclosed, the i-th attribute equals attributeValues[i].
function VerSignature(sig, Disclosure , ipk , msg , attributeValues , rhIndex , revPk , epoch )  {
    // Validate inputs
    /*
	if ipk == nil || revPk == nil {
		return errors.Errorf("cannot verify idemix signature: received nil input")
	}

	if rhIndex < 0 || rhIndex >= len(ipk.AttributeNames) || len(Disclosure) != len(ipk.AttributeNames) {
		return errors.Errorf("cannot verify idemix signature: received invalid input")
	}

	if sig.NonRevocationProof.RevocationAlg != int32(ALG_NO_REVOCATION) && Disclosure[rhIndex] == 1 {
		return errors.Errorf("Attribute %d is disclosed but is also used as revocation handle, which should remain hidden.", rhIndex)
	}
*/

	let HiddenIndices = hiddenIndices(Disclosure)

	// Parse signature
	let APrime = sig.APrime
	let ABar = sig.ABar
    let BPrime = sig.BPrime
    let Nym = sig.Nym
	let ProofC = sig.ProofC
	let ProofSSk = sig.ProofSSk
	let ProofSE = sig.ProofSE
	let ProofSR2 = sig.ProofSR2
	let ProofSR3 = sig.ProofSR3
	let ProofSSPrime = sig.ProofSSPrime
	let ProofSRNym = sig.ProofSRNym
	//let ProofSAttrs = new Array( sig.ProofSAttrs.length)
    let ProofSAttrs =  sig.ProofSAttrs


	if (sig.ProofSAttrs.length != HiddenIndices.length) {
		throw Error("signature invalid: incorrect amount of s-values for AttributeProofSpec")
    }

    sig.ProofSAttrs.forEach(
        (b,i) => {
            ProofSAttrs[i] = new FP256BN.BIG(b)
            //console.log(i,"=> ",b,ProofSAttrs[i])
        }
    )
    let Nonce = sig.Nonce

	// Parse issuer public key
    let W = ipk.W
    let HRand = ipk.HRand
	let HSk = ipk.HSk

	// Verify signature
	if (APrime.is_infinity()) {
		throw  Error("signature invalid: APrime = 1")
	}
	let temp1 = FP256BN.PAIR.ate(W, APrime)
	let temp2 = FP256BN.PAIR.ate(GenG2, ABar)
    temp2.inverse()

	temp1.mul(temp2)

	
    if ( FP256BN.PAIR.fexp(temp1).isunity() ==false ) {
		throw Error("signature invalid: APrime and ABar don't have the expected structure")
	}

	// Verify ZK proof

	// Recover t-values

	// Recompute t1
    //let tt1 = APrime.mul2(ProofSE, HRand, ProofSR2)
    
    let t1  = new FP256BN.ECP()
    t1 = APrime.mul2(ProofSE, HRand, ProofSR2)
	let temp = new FP256BN.ECP()
	temp.copy(ABar)
	temp.sub(BPrime)
	t1.sub(FP256BN.PAIR.G1mul(temp, ProofC))


	// Recompute t2
    let t2 = FP256BN.PAIR.G1mul(HRand, ProofSSPrime)
	t2.add(BPrime.mul2(ProofSR3, HSk, ProofSSk))
	for(i = 0; i < Math.floor(HiddenIndices.length/2); i++) {
		t2.add(ipk.HAttrs[HiddenIndices[2*i]].mul2(ProofSAttrs[2*i], ipk.HAttrs[HiddenIndices[2*i+1]], ProofSAttrs[2*i+1]))
	}
	if (HiddenIndices.length %2 != 0 ) {
		t2.add(FP256BN.PAIR.G1mul(ipk.HAttrs[HiddenIndices[HiddenIndices.length-1]], ProofSAttrs[HiddenIndices.length-1]))
	}
	temp = new FP256BN.ECP()
    temp.copy(GenG1)
    
    Disclosure.forEach(
        (disclose,index) => {
            if (disclose != 0) {
                temp.add(FP256BN.PAIR.G1mul(ipk.HAttrs[index], attributeValues[index]))
            }
        }
    )

	t2.add(FP256BN.PAIR.G1mul(temp, ProofC))

    // Recompute t3
  
    let t3 = new FP256BN.ECP()

    t3 = HSk.mul2(ProofSSk, HRand, ProofSRNym)
	t3.sub(Nym.mul(ProofC))

	// add contribution from the non-revocation proof
/*
    nonRevokedVer, err = getNonRevocationVerifier(RevocationAlgorithm(sig.NonRevocationProof.RevocationAlg))
	if err != nil {
		return err
	}

	i = sort.SearchInts(HiddenIndices, rhIndex)
	proofSRh = ProofSAttrs[i]
	nonRevokedProofBytes, err = nonRevokedVer.recomputeFSContribution(sig.NonRevocationProof, ProofC, Ecp2FromProto(sig.RevocationEpochPk), proofSRh)
	if err != nil {
		return err
	}
*/
	// Recompute challenge
	// proofData is the data being hashed, it consists of:
	// the signature label
	// 7 elements of G1 each taking 2*FieldBytes+1 bytes
	// one bigint (hash of the issuer public key) of length FieldBytes
	// disclosed attributes
    // message that was signed
    
   // proofData = make([]byte, len([]byte(signLabel))+7*(2*FieldBytes+1)+FieldBytes+len(Disclosure)+len(msg)+ProofBytes[RevocationAlgorithm(sig.NonRevocationProof.RevocationAlg)])
    let proofData  = new ArrayBuffer( signLabel.length+7*(2*FieldBytes+1)+FieldBytes+Disclosure.length+msg.length)
    let v = new Uint8Array(proofData)
	index = 0
	index = appendBytesString(v, index, signLabel)
    index = appendBytesG1(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG1(proofData, index, t3)
	index = appendBytesG1(proofData, index, APrime)
	index = appendBytesG1(proofData, index, ABar)
	index = appendBytesG1(proofData, index, BPrime)
	index = appendBytesG1(proofData, index, Nym)
//	index = appendBytes(proofData, index, nonRevokedProofBytes)
    v.set(BigToBytes(ipk.Hash),index);
    index = index + FieldBytes
    v.set(Buffer.from(Disclosure),index);
    index = index + Disclosure.length
    
    v.set(msg,index);
 
    let c = HashModOrder(v)

    index = 0
    proofData = proofData.slice(0,2*FieldBytes);
    let v2 = new Uint8Array(proofData);

	index = appendBytesBig(proofData, index, c)
	index = appendBytesBig(proofData, index, Nonce)

    if (JSON.stringify(ProofC) != JSON.stringify(HashModOrder(v2))) {
        console.log(JSON.stringify(HashModOrder(v2)));
        console.log(JSON.stringify(ProofC));
        throw Error("ignature Verification mismatch")
    }

    /*
	if *ProofC != *HashModOrder(proofData) {
		// This debug line helps identify where the mismatch happened
		idemixLogger.Debugf("Signature Verification : \n"+
			"	[t1:%v]\n,"+
			"	[t2:%v]\n,"+
			"	[t3:%v]\n,"+
			"	[APrime:%v]\n,"+
			"	[ABar:%v]\n,"+
			"	[BPrime:%v]\n,"+
			"	[Nym:%v]\n,"+
			"	[nonRevokedProofBytes:%v]\n,"+
			"	[ipk.Hash:%v]\n,"+
			"	[Disclosure:%v]\n,"+
			"	[msg:%v]\n,",
			EcpToBytes(t1),
			EcpToBytes(t2),
			EcpToBytes(t3),
			EcpToBytes(APrime),
			EcpToBytes(ABar),
			EcpToBytes(BPrime),
			EcpToBytes(Nym),
			nonRevokedProofBytes,
			ipk.Hash,
			Disclosure,
			msg)
		return errors.Errorf("signature invalid: zero-knowledge proof is invalid")
	}

	// Signature is valid
    return nil
    */
}



//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//         MAIN
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */
//**************************************************************************************************************************** */

let AttributeNames = [ "Attr1", "Attr2", "Attr3", "Attr4", "Attr5" ]

//let AttributeNames = [ ]

let key = NewIssuerKey(AttributeNames, rng);
//console.log(key.Ipk);
Check(key.Ipk);


let k = WBBKeyGen(rng);

let mg=FP256BN.BIG.fromBytes(Buffer.from("Hello"));
let mg2=FP256BN.BIG.fromBytes(Buffer.from("Hellno"));

//console.log(mg);
let sig = WBBSign(k.sk,mg);
/*
console.log(sig.toString());
console.log(WBBVerify(k.pk,sig,mg));
console.log(WBBVerify(k.pk,sig,mg2));
*/

let sk2 = RandModOrder(rng);
//let sk2 = RandModOrder(rng);

let nn2 = MakeNym(sk2, key.Ipk, rng);

//sig = NewSignature(cred, sk, Nym, RandNym, key.Ipk, disclosure, msg, rhindex, cri, rng)
let nymsig = NewNymSignature(sk2, nn2.Nym, nn2.RandNym, key.Ipk, Buffer.from("testing"), rng)
//let nymsig2 = NewNymSignature(sk2, nn.Nym, nn.RandNym, key.Ipk, Buffer.from("testing"), rng)
/*
console.log("Test Clé Privé différenteh")
console.log(VerNym( nn.Nym, key.Ipk, Buffer.from("testing"), nymsig))
console.log(VerNym( nn.Nym, key.Ipk, Buffer.from("testing"), nymsig2))
console.log(JSON.stringify(key.Ipk))
console.log(JSON.stringify(nn.Nym))
console.log(JSON.stringify(nn.Nym2))

*/


// Test issuance
let sk = RandModOrder(rng)

ni = RandModOrder(rng)
let m = NewCredRequest(sk, BigToBytes(ni), key.Ipk, rng)

//console.log(JSON.stringify(m));

// Set les valeurs des attributs qui seront signes ds le certificat
let attrs = new Array(AttributeNames.length)
for (i=0;i< AttributeNames.length;i++) {
    attrs[i] = new FP256BN.BIG(i)
}

let cred = NewCredential(key, m, attrs , rng)

//console.log("cred " , cred);
VerCred(cred,sk,key.Ipk)

let disclosure = [ 1, 0 ,0 ,0,0]
//let disclosure = [] 
let msg = Buffer.from("hello5")
msg2 = Buffer.from("hejjkjkllo5")
let rhindex= 4
let cri = null
let nn = MakeNym(sk, key.Ipk, rng)
sig = NewSignature(cred, sk, nn.Nym, nn.RandNym, key.Ipk, disclosure, msg, rhindex, cri, rng)
//console.log(JSON.stringify(sig));

// Là on teste les valeur des attribut.  Seul ceux qui on tles disclosre à 1
// seront verifiés
let attrsvalues = new Array(AttributeNames.length)
for (i=0;i< AttributeNames.length;i++) {
    attrsvalues[i] = new FP256BN.BIG(i)
}

VerSignature(sig, disclosure, key.Ipk, msg, attrsvalues, 0, null, null)
console.log(key.Ipk)