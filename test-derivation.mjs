// Test to compare derivation between JS and C++
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { createHash, pbkdf2Sync } from 'crypto';
import { HDKey } from '@scure/bip32';

// Test mnemonic (use same as in your wallet)
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const passphrase = ""; // empty passphrase

console.log("=== BIP39 Derivation Test ===\n");
console.log("Mnemonic:", mnemonic);
console.log("Passphrase:", passphrase || "(empty)");

// Step 1: Generate BIP39 seed (64 bytes)
const salt = "mnemonic" + passphrase;
const seed = pbkdf2Sync(mnemonic, salt, 2048, 64, 'sha512');
console.log("\n1. BIP39 Seed (64 bytes):", seed.toString('hex'));

// Step 2: Create HD master key
const masterKey = HDKey.fromMasterSeed(seed);
console.log("\n2. Master Key:");
console.log("   Private key:", Buffer.from(masterKey.privateKey).toString('hex'));
console.log("   Chain code:", Buffer.from(masterKey.chainCode).toString('hex'));

// Step 3: Derive path m/100'/1900'/0'/0/0
// BIP32_HARDENED_KEY_LIMIT = 0x80000000
const path = "m/100'/1900'/0'/0/0";
const derived = masterKey.derive(path);
console.log("\n3. Derived key at", path + ":");
console.log("   Private key (32 bytes):", Buffer.from(derived.privateKey).toString('hex'));

// Step 4: Generate ML-DSA-44 key from derived private key
const pqSeed = new Uint8Array(derived.privateKey);
const pqKeys = ml_dsa44.keygen(pqSeed);
console.log("\n4. ML-DSA-44 Keys:");
console.log("   Public key length:", pqKeys.publicKey.length, "bytes");
console.log("   Secret key length:", pqKeys.secretKey.length, "bytes");
console.log("   Public key (first 64 hex):", Buffer.from(pqKeys.publicKey.slice(0, 32)).toString('hex'));

// Step 5: Add 0x05 header and compute Hash160
const pubKeyWithHeader = Buffer.concat([Buffer.from([0x05]), pqKeys.publicKey]);
console.log("\n5. Public key with 0x05 header:", pubKeyWithHeader.length, "bytes");

const sha256Hash = createHash('sha256').update(pubKeyWithHeader).digest();
const hash160 = createHash('ripemd160').update(sha256Hash).digest();
console.log("   Hash160:", hash160.toString('hex'));

// Step 6: Bech32m encode
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
    if (pad) {
        if (bits > 0) {
            result.push((acc << (toBits - bits)) & maxv);
        }
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

function bech32mHrpExpand(hrp) {
    const result = [];
    for (const c of hrp) {
        result.push(c.charCodeAt(0) >> 5);
    }
    result.push(0);
    for (const c of hrp) {
        result.push(c.charCodeAt(0) & 31);
    }
    return result;
}

function bech32mEncode(hrp, data) {
    const combined = [...data, 0, 0, 0, 0, 0, 0];
    const polymod = bech32mPolymod([...bech32mHrpExpand(hrp), ...combined]) ^ BECH32M_CONST;
    const checksum = [];
    for (let i = 0; i < 6; i++) {
        checksum.push((polymod >> (5 * (5 - i))) & 31);
    }
    return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

const data5bit = convertBits(hash160, 8, 5, true);
const witnessVersion = 1;
const address = bech32mEncode('nq', [witnessVersion, ...data5bit]);

console.log("\n6. Final PQ Address:", address);

console.log("\n=== Use these values to compare with C++ output ===");
