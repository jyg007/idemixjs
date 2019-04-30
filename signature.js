
const util = require("./utils.js");

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
const Modsub=util.Modsub

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
function NewSignature(cred , sk , Nym , RNym , ipk , Disclosure , msg , rhIndex , cri  ) {
    
    /*
    // Validate inputs
	if cred == nil || sk == nil || Nym == nil || RNym == nil || ipk == nil || util.rng == nil || cri == nil {
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
	let r1 = RandModOrder(util.rng)
	let r2 = RandModOrder(util.rng)
	// Set r_3 as \frac{1}{r_1}
    let r3 = new FP256BN.BIG(r1)

	r3.invmodp(GroupOrder)

	// Sample a nonce
	let Nonce = RandModOrder(util.rng)

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
	let rSk = RandModOrder(util.rng)
	let re = RandModOrder(util.rng)
	let rR2 = RandModOrder(util.rng)
	let rR3 = RandModOrder(util.rng)
	let rSPrime = RandModOrder(util.rng)
	let rRNym = RandModOrder(util.rng)

    let rAttrs = new Array(HiddenIndices.length)
    HiddenIndices.forEach(
        (value,i) => {
            rAttrs[i] = RandModOrder(util.rng)
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
		util.rng,
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
	let proofData  = new ArrayBuffer( util.signLabel.length+7*(2*FieldBytes+1)+FieldBytes+Disclosure.length+msg.length)
    let v = new Uint8Array(proofData);
    let index = 0
	index = appendBytesString(v, index, util.signLabel)
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
    let proofData  = new ArrayBuffer( util.signLabel.length+7*(2*FieldBytes+1)+FieldBytes+Disclosure.length+msg.length)
    let v = new Uint8Array(proofData)
	index = 0
	index = appendBytesString(v, index, util.signLabel)
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

module.exports = {
    NewSignature:NewSignature,
    VerSignature:VerSignature,
}