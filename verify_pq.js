const crypto = require('crypto');
const DilithiumAlgorithm = require('./dilithium_node.js');

const isTestnet = process.argv.includes('--testnet') || process.argv.includes('testnet');
const hrp = isTestnet ? 'tnq' : 'nq';
const networkName = isTestnet ? 'testnet' : 'mainnet';

// Bech32m Implementation (copied from index.js)
function bech32_polymod(values) {
    var GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var p = 0; p < values.length; ++p) {
        var top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[p];
        for (var i = 0; i < 5; ++i) {
            if ((top >> i) & 1) {
                chk ^= GENERATOR[i];
            }
        }
    }
    return chk;
}

function bech32_hrpExpand(hrp) {
    var ret = [];
    for (var i = 0; i < hrp.length; ++i) {
        ret.push(hrp.charCodeAt(i) >> 5);
    }
    ret.push(0);
    for (var i = 0; i < hrp.length; ++i) {
        ret.push(hrp.charCodeAt(i) & 31);
    }
    return ret;
}

function bech32m_createChecksum(hrp, data) {
    var values = bech32_hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    var polymod = bech32_polymod(values) ^ 0x2bc830a3;
    var ret = [];
    for (var i = 0; i < 6; ++i) {
        ret.push((polymod >> 5 * (5 - i)) & 31);
    }
    return ret;
}

function bech32m_encode(hrp, data) {
    var combined = data.concat(bech32m_createChecksum(hrp, data));
    var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    var ret = hrp + '1';
    for (var i = 0; i < combined.length; ++i) {
        ret += CHARSET.charAt(combined[i]);
    }
    return ret;
}

function convertBits(data, fromBits, toBits, pad) {
    var acc = 0;
    var bits = 0;
    var ret = [];
    var maxv = (1 << toBits) - 1;
    for (var p = 0; p < data.length; ++p) {
        var value = data[p];
        if (value < 0 || (value >> fromBits) !== 0) {
            return null;
        }
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) {
            ret.push((acc << (toBits - bits)) & maxv);
        }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
        return null;
    }
    return ret;
}

function hash160(buffer) {
    const sha = crypto.createHash('sha256').update(buffer).digest();
    return crypto.createHash('ripemd160').update(sha).digest();
}

function taggedHash(tag, msg) {
    const tagHash = crypto.createHash('sha256').update(Buffer.from(tag, 'utf8')).digest();
    return crypto.createHash('sha256').update(Buffer.concat([tagHash, tagHash, Buffer.from(msg)])).digest();
}

console.log(`Starting Neurai PQ Logic Verification (${networkName})...`);

try {
    const seed = crypto.randomBytes(32);
    console.log('\n[1] Derived Seed (32 bytes):');
    console.log(seed.toString('hex'));

    console.log('\n[2] Generating Dilithium2 Keypair...');
    var level2 = DilithiumAlgorithm.DilithiumLevel.get(2);
    var pqKeyPair = DilithiumAlgorithm.DilithiumKeyPair.generate(level2, new Uint8Array(seed));

    var pubKeyBytes = pqKeyPair.getPublicKey().getBytes();
    console.log('\n[3] Dilithium Public Key (first 64 bytes):');
    console.log(Buffer.from(pubKeyBytes).slice(0, 64).toString('hex') + '...');
    console.log('Total Length:', pubKeyBytes.length, 'bytes');

    // Match Neurai AuthScript default PQ address generation.
    var pubKeyWithHeader = Buffer.concat([Buffer.from([0x05]), Buffer.from(pubKeyBytes)]);
    var keyHashBuffer = hash160(pubKeyWithHeader);
    console.log('\n[4] Hash160 of 0x05 || PQ Public Key:');
    console.log(keyHashBuffer.toString('hex'));

    var witnessScript = Buffer.from([0x51]); // OP_TRUE
    var witnessScriptHash = crypto.createHash('sha256').update(witnessScript).digest();
    console.log('\n[5] SHA256(OP_TRUE):');
    console.log(witnessScriptHash.toString('hex'));

    var preimage = Buffer.concat([Buffer.from([0x01, 0x01]), keyHashBuffer, witnessScriptHash]);
    var commitmentBuffer = taggedHash('NeuraiAuthScript', preimage);
    console.log('\n[6] AuthScript commitment:');
    console.log(commitmentBuffer.toString('hex'));

    var commitmentArray = [];
    for (var i = 0; i < commitmentBuffer.length; i++) commitmentArray.push(commitmentBuffer[i]);

    var data5bit = convertBits(commitmentArray, 8, 5, true);
    var version = [1];
    var data = version.concat(data5bit);
    var address = bech32m_encode(hrp, data);

    console.log(`\n[7] Generated Neurai PQ ${networkName} Address:`);
    console.log(address);

    if (address.startsWith(hrp + '1')) {
        console.log(`\nSUCCESS: Address format looks correct (starts with ${hrp}1)!`);
    } else {
        console.error('\nFAILURE: Address format incorrect.');
    }
} catch (e) {
    console.error('Verification Failed:', e);
}
