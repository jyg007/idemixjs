
const util = require("./utils.js");

/************************************************************************************* */
function WBBKeyGen() {
    let k =  { pk : "", sk : "" };
    k.sk = util.RandModOrder(util.rng);
    k.pk = util.GenG2.mul(k.sk);
    return k;    
}

/************************************************************************************* */
function WBBSign(sk, m) {
    let exp = util.Modadd(sk,util.FP256BN.BIG.fromBytes(m),util.GroupOrder);
    exp.invmodp(util.GroupOrder);
    return util.GenG1.mul(exp);
}

/************************************************************************************* */
function WBBVerify(pk, sig, m) {
    let p = new util.FP256BN.ECP2();
    p.copy(pk);
    p.add(util.GenG2.mul(util.FP256BN.BIG.fromBytes(m)));
    p.affine();
    let o=util.FP256BN.PAIR.fexp(util.FP256BN.PAIR.ate(p,sig));
    return util.GenGT.equals(o);
}

module.exports = {
    WBBKeyGen: WBBKeyGen,
    WBBSign: WBBSign,
    WBBVerify: WBBVerify,
}
