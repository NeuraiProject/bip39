// Test to compare NIP-022 PQ-HD derivation between JS and C++
// Implements CKDer_PQ: HMAC-SHA512("Neurai PQ seed", bip39_seed) for master,
// then HMAC-SHA512(cc_parent, 0x00 || pq_seed_parent || ser32(index)) for each child.
// All derivation levels are hardened (index >= 0x80000000).
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash, createHmac, pbkdf2Sync } from 'crypto';

const isTestnet = process.argv.includes('--testnet') || process.argv.includes('testnet');
const networkName = isTestnet ? 'testnet' : 'mainnet';
const hrp = isTestnet ? 'tnq' : 'nq';
const PQ_PURPOSE   = 100;
const PQ_COIN_TYPE = isTestnet ? 1 : 1900;
const PQ_ACCOUNT   = 0;
const PQ_CHANGE    = 0;
const PQ_INDEX     = 0;
const path = `m_pq/${PQ_PURPOSE}'/${PQ_COIN_TYPE}'/${PQ_ACCOUNT}'/${PQ_CHANGE}'/${PQ_INDEX}'`;

const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const passphrase = '';

console.log(`=== NIP-022 PQ-HD Derivation Test (${networkName}) ===\n`);
console.log('Mnemonic:', mnemonic);
console.log('Passphrase:', passphrase || '(empty)');
console.log('Network:', networkName);
console.log('Derivation path:', path);
console.log('HRP:', hrp);

const salt = 'mnemonic' + passphrase;
const seed = pbkdf2Sync(mnemonic, salt, 2048, 64, 'sha512');
console.log('\n1. BIP39 Seed (64 bytes):', seed.toString('hex'));

// NIP-022 master: HMAC-SHA512("Neurai PQ seed", bip39_seed)
function nip022Master(bip39Seed) {
    const out = createHmac('sha512', 'Neurai PQ seed').update(bip39Seed).digest();
    return { pq_seed: out.slice(0, 32), cc: out.slice(32, 64) };
}

// CKDer_PQ: HMAC-SHA512(cc_parent, 0x00 || pq_seed_parent || ser32(index))
function nip022CkderPQ(parent, index) {
    if (index < 0x80000000) throw new Error('NIP-022: only hardened derivation');
    const data = Buffer.alloc(37);
    data[0] = 0x00;
    parent.pq_seed.copy(data, 1);
    data.writeUInt32BE(index, 33);
    const out = createHmac('sha512', parent.cc).update(data).digest();
    return { pq_seed: out.slice(0, 32), cc: out.slice(32, 64) };
}

function nip022Derive(bip39Seed, purpose, coin, account, change, leafIndex) {
    const H = 0x80000000;
    let node = nip022Master(bip39Seed);
    node = nip022CkderPQ(node, (purpose    + H) >>> 0);
    node = nip022CkderPQ(node, (coin       + H) >>> 0);
    node = nip022CkderPQ(node, (account    + H) >>> 0);
    node = nip022CkderPQ(node, (change     + H) >>> 0);
    node = nip022CkderPQ(node, (leafIndex  + H) >>> 0);
    return node.pq_seed;
}

const masterNode = nip022Master(seed);
console.log('\n2. NIP-022 Master (HMAC-SHA512("Neurai PQ seed", bip39_seed)):');
console.log('   pq_seed:', masterNode.pq_seed.toString('hex'));
console.log('   chaincode:', masterNode.cc.toString('hex'));

const pqSeedBuf = nip022Derive(seed, PQ_PURPOSE, PQ_COIN_TYPE, PQ_ACCOUNT, PQ_CHANGE, PQ_INDEX);
console.log('\n3. Derived leaf at', path + ':');
console.log('   pq_seed (32 bytes):', pqSeedBuf.toString('hex'));

const pqSeed = new Uint8Array(pqSeedBuf);
const pqKeys = ml_dsa44.keygen(pqSeed);
console.log('\n4. ML-DSA-44 Keys:');
console.log('   Public key length:', pqKeys.publicKey.length, 'bytes');
console.log('   Secret key length:', pqKeys.secretKey.length, 'bytes');
console.log('   Public key (first 64 hex):', Buffer.from(pqKeys.publicKey.slice(0, 32)).toString('hex'));

const pubKeyWithHeader = Buffer.concat([Buffer.from([0x05]), pqKeys.publicKey]);
const keyHash = createHash('ripemd160').update(createHash('sha256').update(pubKeyWithHeader).digest()).digest();
console.log('\n5. Hash160(0x05 || pubkey):', keyHash.toString('hex'));

const witnessScript = Buffer.from([0x51]);
const witnessScriptHash = createHash('sha256').update(witnessScript).digest();
console.log('6. SHA256(OP_TRUE):', witnessScriptHash.toString('hex'));

function taggedHash(tag, msg) {
    const tagHash = createHash('sha256').update(Buffer.from(tag, 'utf8')).digest();
    return createHash('sha256').update(Buffer.concat([tagHash, tagHash, Buffer.from(msg)])).digest();
}

const preimage = Buffer.concat([Buffer.from([0x01, 0x01]), keyHash, witnessScriptHash]);
const commitment = taggedHash('NeuraiAuthScript', preimage);
console.log('7. AuthScript commitment:', commitment.toString('hex'));

function convertBits(data, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const result = [];
    const maxv = (1 << toBits) - 1;
    for (const value of data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            result.push((acc >> bits) & maxv);
        }
    }
    if (pad && bits > 0) {
        result.push((acc << (toBits - bits)) & maxv);
    }
    return result;
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;

function bech32mPolymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) {
            if ((b >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

function bech32mHrpExpand(value) {
    const result = [];
    for (const c of value) {
        result.push(c.charCodeAt(0) >> 5);
    }
    result.push(0);
    for (const c of value) {
        result.push(c.charCodeAt(0) & 31);
    }
    return result;
}

function bech32mEncode(value, data) {
    const combined = [...data, 0, 0, 0, 0, 0, 0];
    const polymod = bech32mPolymod([...bech32mHrpExpand(value), ...combined]) ^ BECH32M_CONST;
    const checksum = [];
    for (let i = 0; i < 6; i++) {
        checksum.push((polymod >> (5 * (5 - i))) & 31);
    }
    return value + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

const data5bit = convertBits(commitment, 8, 5, true);
const witnessVersion = 1;
const address = bech32mEncode(hrp, [witnessVersion, ...data5bit]);

console.log(`\n8. Final PQ ${networkName} Address:`, address);

// 9. xpqpriv / tpqpriv master extended key (74-byte padded layout)
const VERSION_MAIN = Buffer.from([0x04, 0x88, 0xAC, 0x24]); // xpqp...
const VERSION_TEST = Buffer.from([0x04, 0x35, 0x81, 0xD5]); // tpqp...
const extVersion = isTestnet ? VERSION_TEST : VERSION_MAIN;
const extPayload = Buffer.alloc(78);
extVersion.copy(extPayload, 0);
masterNode.cc.copy(extPayload, 13);
// extPayload[45] = 0x00 padding (already zero)
masterNode.pq_seed.copy(extPayload, 46);
const extChk = createHash('sha256').update(createHash('sha256').update(extPayload).digest()).digest().slice(0, 4);
const extFull = Buffer.concat([extPayload, extChk]);
const B58A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(buf) {
    let n = 0n;
    for (const b of buf) n = n * 256n + BigInt(b);
    let s = '';
    while (n > 0n) { s = B58A[Number(n % 58n)] + s; n /= 58n; }
    for (const b of buf) { if (b === 0) s = '1' + s; else break; }
    return s;
}
const extKey = base58(extFull);
console.log(`\n9. Master extended PQ private key (${isTestnet ? 'tpqpriv' : 'xpqpriv'}):`);
console.log('  ', extKey);

console.log('\n=== Use these values to compare with C++ output ===');
