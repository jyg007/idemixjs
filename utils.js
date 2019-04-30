const c = require('./js/ctx.js')
const FP256BN =  new c.CTX('FP256BN');
const fs = require('fs');

const crypto = require('crypto');

//RandModOrder  
function LOG(a,msg) {
    console.log("\n===========================================\n",msg,"\n===========================================\n",JSON.stringify(a),"\n")
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

let bu= new ArrayBuffer(512);

let buffer = Buffer.from(bu);
let fd=fs.openSync('/dev/urandom','r');
let n = fs.readSync(fd, buffer, 0, 512, 0);
fs.closeSync(fd);

let rng=new FP256BN.RAND();
rng.clean();
rng.seed(1512,buffer);

module.exports=  {
    FP256BN: FP256BN,
    Modadd: Modadd,
    Modsub:Modsub,
    HashModOrder: HashModOrder,
    RandModOrder: RandModOrder,
    rng:rng,
    GenG2:GenG2,
    GenG1:GenG1,
    GenGT:GenGT,
    GroupOrder: GroupOrder,
    appendBytesG2:appendBytesG2,
    appendBytesG1:appendBytesG1,
    appendBytesString:appendBytesString,
    appendBytesBig:appendBytesBig,
    appendBytes:appendBytes,
    FieldBytes: FieldBytes,
    signLabel: signLabel,
    BigToBytes:BigToBytes,
    LOG:LOG,

}