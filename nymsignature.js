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

//****************************************************************************************************************** */
function MakeNym(sk , IPk ) {
    let k = { Nym : "", RandNym :""};
	// Construct a commitment to the sk
	// Nym = h_{sk}^sk \cdot h_r^r
	k.RandNym = RandModOrder(util.rng)
	k.Nym = IPk.HSk.mul2(sk, IPk.HRand, k.RandNym)
	return k
}

//****************************************************************************************************************** */
//Sign produces a signature over the passed digest. 
//It takes in input, the user secret key (sk), 
//the pseudonym public key (Nym) and secret key (RNym), 
//and the issuer public key (ipk).

function NewNymSignature(sk, Nym , RNym , ipk , msg  )  {
	let Nonce = RandModOrder(util.rng)

	let HRand = ipk.HRand;
	let HSk = ipk.HSk;

	// The rest of this function constructs the non-interactive zero knowledge proof proving that
	// the signer 'owns' this pseudonym, i.e., it knows the secret key and randomness on which it is based.
	// Recall that (Nym,RNym) is the output of MakeNym. Therefore, Nym = h_{sk}^sk \cdot h_r^r

	// Sample the randomness needed for the proof
	let rSk = RandModOrder(util.rng)
	let rRNym = RandModOrder(util.rng)

	// Step 1: First message (t-values)
	let t = HSk.mul2(rSk, HRand, rRNym) // t = h_{sk}^{r_sk} \cdot h_r^{r_{RNym}

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData will hold the data being hashed, it consists of:
	// - the signature label
	// - 2 elements of G1 each taking 2*FieldBytes+1 bytes
	// - one bigint (hash of the issuer public key) of length FieldBytes
	// - disclosed attributes
	// - message being signed
    let proofData = new ArrayBuffer(util.signLabel.length+2*(2*FieldBytes+1)+FieldBytes+msg.length);
    let v = new Uint8Array(proofData);

    let index = 0

    index = appendBytesString(v, index, util.signLabel)
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
    let proofData = new ArrayBuffer(util.signLabel.length+2*(2*FieldBytes+1)+FieldBytes+msg.length);
    let v = new Uint8Array(proofData);
	let index = 0
	index = appendBytesString(v, index, util.signLabel)
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

module.exports = {
    NewNymSignature:NewNymSignature,
    MakeNym:MakeNym,
    VerNym:VerNym,
}