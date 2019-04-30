const c = require('./js/ctx.js')
const util = require("./utils.js")
const NIST384 =  new c.CTX('NIST384')
//const wbb = require("./weak-bb.js")


// GenerateLongTermRevocationKey generates a long term signing key that will be used for revocation
function GenerateLongTermRevocationKey() {
    let S0=[];
    let W0=[];

    NIST384.ECDH.KEY_PAIR_GENERATE(util.rng,S0,W0); 
    return { sk: S0, pk:W0 }
}


// CreateCRI creates the Credential Revocation Information for a certain time period (epoch).
// Users can use the CRI to prove that they are not revoked.
// Note that when not using revocation (i.e., alg = ALG_NO_REVOCATION), the entered unrevokedHandles are not used,
// and the resulting CRI can be used by any signer.
function CreateCRI(key , epoch , alg)  {
	//if key == nil || rng == nil {
	//	return nil, errors.Errorf("CreateCRI received nil input")
	//}
	let cri = {
            RevocationAlg :alg,
            Epoch : epoch
        }

	if (alg == "ALG_NO_REVOCATION") {
		// put a dummy PK in the proto
		cri.EpochPk = util.GenG2
	} else {
		// create epoch key
	 //   epochKey =  wbb.WBBKeyGen()
		//cri.EpochPk = epochKey.pk
	}

	// sign epoch + epoch key with long term key

    digest = util.HashModOrder(JSON.stringify(cri))

    let CS = new ArrayBuffer()
    let DS = new ArrayBuffer()
    let digestBuffer = new ArrayBuffer() 
    digest.toBytes(digestBuffer)

     if (NIST384.ECDH.ECPSP_DSA(NIST384.ECP.HASH_TYPE,util.rng,key,digestBuffer,CS,DS)!=0)
        throw Error("***ECDSA Signature Failed");

    cri.EpochPkSig  = { C:CS, D:DS }

	if (alg == "ALG_NO_REVOCATION") {
		return cri
	} else {
		throw Error("the specified revocation algorithm is not supported.")
	}
}


// VerifyEpochPK verifies that the revocation PK for a certain epoch is valid,
// by checking that it was signed with the long term revocation key.
// Note that even if we use no revocation (i.e., alg = ALG_NO_REVOCATION), we need
// to verify the signature to make sure the issuer indeed signed that no revocation
// is used in this epoch.
function VerifyEpochPK(pk , epochPK , epochPkSig , epoch , alg )  {
    //if pk == nil || epochPK == nil {
	//	return errors.Errorf("EpochPK invalid: received nil input")
    //}

	let cri = {
        RevocationAlg : alg,
        Epoch : epoch,
        EpochPk : epochPK,
    }
    

    digest = util.HashModOrder(JSON.stringify(cri))


    let CS = new ArrayBuffer()
    let DS = new ArrayBuffer()
    let digestBuffer = new ArrayBuffer() 
    digest.toBytes(digestBuffer)


    if (NIST384.ECDH.ECPVP_DSA(NIST384.ECP.HASH_TYPE,pk,digestBuffer,epochPkSig.C,epochPkSig.D)!=0)
        throw Error("EpochPKSig invalid")

    

}


module.exports=  {
    GenerateLongTermRevocationKey:GenerateLongTermRevocationKey,
    CreateCRI: CreateCRI,
    VerifyEpochPK:VerifyEpochPK
}