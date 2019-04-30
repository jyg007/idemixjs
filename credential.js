
const util = require("./utils.js");
const credrequest = require("./credrequest.js")

const FP256BN = util.FP256BN
const GenG1 = util.GenG1
const GenG2 = util.GenG2

const FieldBytes = util.FieldBytes

const RandModOrder=util.RandModOrder
const appendBytesG1=util.appendBytesG1
const HashModOrder=util.HashModOrder
const appendBytesString=util.appendBytesString
const BigToBytes=util.BigToBytes
const appendBytesBig=util.appendBytesBig
const Modadd=util.Modadd
const GroupOrder=util.GroupOrder
const appendBytes=util.appendBytes



//****************************************************************************************************************** */
//****************************************************************************************************************** */
function NewCredential(key , m , attrs )  {

	credrequest.CheckCredReq(m,key.Ipk)

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
	let E = RandModOrder(util.rng)
	let S = RandModOrder(util.rng)

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
		BPrime.add(ipk.HAttrs[cred.Attrs.length-1].mul(cred.Attrs[cred.Attrs.length-1]))
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

module.exports = {
    NewCredential:NewCredential,
    VerCred:VerCred,
}