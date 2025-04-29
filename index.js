"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptedPayload = exports.DoubleRatchetSession = void 0;
exports.encodeUTF8 = encodeUTF8;
exports.decodeUTF8 = decodeUTF8;
exports.encodeBase64 = encodeBase64;
exports.decodeBase64 = decodeBase64;
exports.numberFromUint8Array = numberFromUint8Array;
exports.numberToUint8Array = numberToUint8Array;
exports.createDoubleRatchetSession = createDoubleRatchetSession;
const fast_sha256_1 = require("fast-sha256");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const tweetnacl_util_1 = __importDefault(require("tweetnacl-util"));
function encodeUTF8(array) {
    const decoder = new TextDecoder();
    return decoder.decode(array);
}
function decodeUTF8(string) {
    const encoder = new TextEncoder();
    return encoder.encode(string);
}
function encodeBase64(array) {
    return tweetnacl_util_1.default.encodeBase64(array !== null && array !== void 0 ? array : new Uint8Array());
}
function decodeBase64(string) {
    return tweetnacl_util_1.default.decodeBase64(string !== null && string !== void 0 ? string : "");
}
function numberFromUint8Array(array) {
    let total = 0;
    if (array)
        for (let c = 0; c < EncryptedPayloadConstructor.countLength; c++)
            total += array[c] << (c * 8);
    return total;
}
function numberToUint8Array(number, length) {
    if (!number)
        return new Uint8Array(length !== null && length !== void 0 ? length : 0).fill(0);
    const arr = [];
    while (number > 0) {
        arr.push(number & 255);
        number = number >>> 8;
    }
    const out = new Uint8Array(length !== null && length !== void 0 ? length : arr.length);
    out.set(arr);
    return out;
}
function verifyUint8Array(a, b) {
    return tweetnacl_1.default.verify(a !== null && a !== void 0 ? a : new Uint8Array(), b !== null && b !== void 0 ? b : new Uint8Array());
}
function createDoubleRatchetSession(remoteKey) {
    return new DoubleRatchetSessionConstructor(remoteKey);
}
class DoubleRatchetSession {
    constructor(remoteKey) {
        return new DoubleRatchetSessionConstructor(remoteKey);
    }
}
exports.DoubleRatchetSession = DoubleRatchetSession;
DoubleRatchetSession.keyLength = 32;
class DoubleRatchetSessionConstructor {
    constructor(remoteKey) {
        this.keyPair = tweetnacl_1.default.box.keyPair();
        this.sendingCount = 0;
        this.receivingCount = 0;
        this.previusCount = 0;
        this.previusKeys = [];
        if (remoteKey) {
            this._remoteKey = remoteKey;
            this.sendingChain = this.dhRatchet();
        }
    }
    get handshaked() { return this.sendingChain && this.receivingChain ? true : false; }
    get publicKey() { return this.keyPair.publicKey; }
    get remoteKey() { return this._remoteKey; }
    //public set remoteKey(key: Uint8Array) { this.setRemoteKey(key); }
    setRemoteKey(key) {
        this._remoteKey = key;
        this.receivingChain = this.dhRatchet();
        this.previusCount = this.receivingCount;
        this.receivingCount = 0;
        this.keyPair = tweetnacl_1.default.box.keyPair();
        this.sendingChain = this.dhRatchet();
        this.sendingCount = 0;
        return this;
    }
    dhRatchet(info) {
        if (!this._remoteKey)
            throw new Error();
        const sharedKey = tweetnacl_1.default.scalarMult(this.keyPair.secretKey, this._remoteKey);
        if (!this.rootKey)
            this.rootKey = this.rootKey = (0, fast_sha256_1.hash)(sharedKey);
        const hashkey = (0, fast_sha256_1.hkdf)(sharedKey, this.rootKey, info, DoubleRatchetSession.keyLength * 2);
        this.rootKey = hashkey.slice(0, DoubleRatchetSession.keyLength);
        return hashkey.slice(DoubleRatchetSession.keyLength);
    }
    getSendingKey() {
        if (!this.sendingChain)
            throw new Error;
        const out = DoubleRatchetSessionConstructor.symmetricRatchet(this.sendingChain);
        this.sendingChain = out[0];
        this.sendingCount++;
        return out[1];
    }
    getReceivingKey() {
        if (!this.receivingChain)
            throw new Error();
        const out = DoubleRatchetSessionConstructor.symmetricRatchet(this.receivingChain);
        this.receivingChain = out[0];
        this.receivingCount++;
        return out[1];
    }
    encrypt(payload) {
        payload !== null && payload !== void 0 ? payload : (payload = new Uint8Array());
        try {
            const key = this.getSendingKey();
            if (this.sendingCount >= EncryptedPayloadConstructor.maxCount || this.previusCount >= EncryptedPayloadConstructor.maxCount)
                throw new Error();
            const nonce = tweetnacl_1.default.randomBytes(EncryptedPayloadConstructor.nonceLength);
            const ciphertext = tweetnacl_1.default.secretbox(payload, nonce, key);
            return new EncryptedPayloadConstructor(this.sendingCount, this.previusCount, this.keyPair.publicKey, nonce, ciphertext);
        }
        catch (error) {
            return undefined;
        }
    }
    decrypt(payload) {
        var _a;
        if (!payload)
            return undefined;
        try {
            const encrypted = EncryptedPayload.from(payload);
            const publicKey = encrypted.publicKey;
            if (!verifyUint8Array(publicKey, this._remoteKey)) {
                for (let i = this.receivingCount; i < encrypted.previous; i++) {
                    this.previusKeys.unshift(this.getReceivingKey());
                }
                this.setRemoteKey(publicKey);
            }
            let cleartext;
            const count = encrypted.count;
            if (this.receivingCount < count) {
                for (let i = this.receivingCount; i < count; i++) {
                    this.previusKeys.unshift(this.getReceivingKey());
                }
                const key = this.previusKeys.shift();
                if (!key)
                    return undefined;
                cleartext = (_a = tweetnacl_1.default.secretbox.open(encrypted.ciphertext, encrypted.nonce, key)) !== null && _a !== void 0 ? _a : undefined;
            }
            else {
                this.previusKeys.filter((key) => {
                    var _a;
                    if (cleartext)
                        return true;
                    return !(cleartext = (_a = tweetnacl_1.default.secretbox.open(encrypted.ciphertext, encrypted.nonce, key)) !== null && _a !== void 0 ? _a : undefined);
                });
            }
            return cleartext;
        }
        catch (error) {
            return undefined;
        }
    }
    static symmetricRatchet(chain, salt, info) {
        const hash = (0, fast_sha256_1.hkdf)(chain, salt, info, DoubleRatchetSession.keyLength * 2);
        return [new Uint8Array(hash.buffer, 0, DoubleRatchetSession.keyLength), new Uint8Array(hash.buffer, DoubleRatchetSession.keyLength)];
    }
}
class EncryptedPayload {
    static from(array) {
        return new EncryptedPayloadConstructor(array);
    }
}
exports.EncryptedPayload = EncryptedPayload;
class EncryptedPayloadConstructor extends Uint8Array {
    constructor(...arrays) {
        arrays = arrays.filter(value => value !== undefined);
        if (typeof arrays[0] === 'number') {
            arrays[0] = numberToUint8Array(arrays[0], EncryptedPayloadConstructor.countLength);
        }
        if (typeof arrays[1] === 'number') {
            arrays[1] = numberToUint8Array(arrays[1], EncryptedPayloadConstructor.countLength);
        }
        const uintarray = new Uint8Array(arrays.map(value => value.length).reduce((prev, curr) => prev + curr));
        let offset = 0;
        arrays.forEach(arr => {
            uintarray.set(arr, offset);
            offset += arr.length;
        });
        super(uintarray);
    }
    /*public get signed() { return (this[EncryptedPayloadConstructor.countLength - 1] & 128) > 0; }
    public set signed(value: boolean) {
        if (value)
            this[EncryptedPayloadConstructor.countLength - 1] |= 128;
        else
            this[EncryptedPayloadConstructor.countLength - 1] &= 127;
    }

    public setSigned() {
        this[EncryptedPayloadConstructor.countLength - 1] |= 128;
        return this;
    }*/
    get count() {
        let total = numberFromUint8Array(new Uint8Array(this.buffer, ...Offsets.count.get));
        total &= 2 ** (EncryptedPayloadConstructor.countLength * 8 - 1) - 1;
        return total;
    }
    get previous() {
        return numberFromUint8Array(new Uint8Array(this.buffer, ...Offsets.previous.get));
    }
    get publicKey() { return new Uint8Array(this.buffer, ...Offsets.publicKey.get); }
    get nonce() { return new Uint8Array(this.buffer, ...Offsets.nonce.get); }
    get ciphertext() { return new Uint8Array(this.buffer, Offsets.ciphertext.start); }
    encode() { return new Uint8Array(this); }
    decode() {
        return {
            count: this.count,
            previus: this.previous,
            publicKey: encodeBase64(this.publicKey),
            nonce: encodeBase64(this.nonce),
            ciphertext: encodeUTF8(this.ciphertext),
            //signed: this.signed
        };
    }
    toString() {
        return encodeUTF8(this);
    }
    toJSON() {
        return JSON.stringify(this.decode());
    }
    static from(array) {
        return new EncryptedPayloadConstructor(array);
    }
}
EncryptedPayloadConstructor.signatureLength = tweetnacl_1.default.sign.signatureLength;
EncryptedPayloadConstructor.secretKeyLength = tweetnacl_1.default.box.secretKeyLength;
EncryptedPayloadConstructor.publicKeyLength = tweetnacl_1.default.box.publicKeyLength;
EncryptedPayloadConstructor.keyLength = tweetnacl_1.default.secretbox.keyLength;
EncryptedPayloadConstructor.nonceLength = tweetnacl_1.default.secretbox.nonceLength;
EncryptedPayloadConstructor.maxCount = 65536; //32768;
EncryptedPayloadConstructor.countLength = 2;
class Offsets {
    static set(start, length) {
        class Offset {
            constructor(start, length) {
                this.start = start;
                this.length = length;
                if (typeof length === 'number')
                    this.end = start + length;
            }
            get get() {
                return [this.start, this.length];
            }
        }
        return new Offset(start, length);
    }
}
Offsets.count = Offsets.set(0, EncryptedPayloadConstructor.countLength);
Offsets.previous = Offsets.set(Offsets.count.end, EncryptedPayloadConstructor.countLength);
Offsets.publicKey = Offsets.set(Offsets.previous.end, EncryptedPayloadConstructor.publicKeyLength);
Offsets.nonce = Offsets.set(Offsets.publicKey.end, EncryptedPayloadConstructor.nonceLength);
Offsets.ciphertext = Offsets.set(Offsets.nonce.end, undefined);
