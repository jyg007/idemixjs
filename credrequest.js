
const util = require("./utils.js");

const FP256BN = util.FP256BN
const GenG1 = util.GenG1
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
const credRequestLabel = "credRequest"


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
function NewCredRequest(sk , IssuerNonce , ipk  )  {
	// Set Nym as h_{sk}^{sk}
	let HSk = ipk.HSk
	let Nym = HSk.mul(sk)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key

	// Sample the randomness needed for the proof
	let rSk = RandModOrder(util.rng)

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


module.exports = {
    CheckCredReq:CheckCredReq,
    NewCredRequest:NewCredRequest,
}