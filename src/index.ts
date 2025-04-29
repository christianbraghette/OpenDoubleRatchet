import { hkdf, hash } from "fast-sha256";
import nacl from "tweetnacl";
import util from "tweetnacl-util"

export function encodeUTF8(array?: Uint8Array): string {
    const decoder = new TextDecoder();
    return decoder.decode(array);
}

export function decodeUTF8(string?: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(string);
}

export function encodeBase64(array?: Uint8Array): string {
    return util.encodeBase64(array ?? new Uint8Array());
}

export function decodeBase64(string?: string): Uint8Array {
    return util.decodeBase64(string ?? "");
}

export function numberFromUint8Array(array?: Uint8Array): number {
    let total = 0;
    if (array)
        for (let c = 0; c < EncryptedPayloadConstructor.countLength; c++)
            total += array[c] << (c * 8);
    return total;
}

export function numberToUint8Array(number?: number, length?: number): Uint8Array {
    if (!number) return new Uint8Array(length ?? 0).fill(0);
    const arr: number[] = [];
    while (number > 0) {
        arr.push(number & 255);
        number = number >>> 8;
    }
    const out = new Uint8Array(length ?? arr.length);
    out.set(arr);
    return out;
}

function verifyUint8Array(a?: Uint8Array, b?: Uint8Array): boolean {
    return nacl.verify(a ?? new Uint8Array(), b ?? new Uint8Array())
}

export function createDoubleRatchetSession(remoteKey?: Uint8Array): DoubleRatchetSession {
    return new DoubleRatchetSessionConstructor(remoteKey);
}

export interface DoubleRatchetSession {
    readonly handshaked: boolean;
    readonly publicKey: Uint8Array;
    readonly remoteKey: Uint8Array | undefined;

    encrypt(payload: Uint8Array): EncryptedPayload | undefined;
    decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined;
}
export class DoubleRatchetSession {

    public constructor(remoteKey?: Uint8Array) {
        return new DoubleRatchetSessionConstructor(remoteKey);
    }

    public static readonly keyLength = 32;
}

class DoubleRatchetSessionConstructor implements DoubleRatchetSession {

    private keyPair = nacl.box.keyPair();
    private _remoteKey?: Uint8Array;
    private rootKey?: Uint8Array;
    private sendingChain?: Uint8Array;
    private sendingCount = 0;
    private receivingChain?: Uint8Array;
    private receivingCount = 0;
    private previusCount = 0;
    private previusKeys: Uint8Array[] = [];

    public constructor(remoteKey?: Uint8Array) {
        if (remoteKey) {
            this._remoteKey = remoteKey;
            this.sendingChain = this.dhRatchet();
        }
    }

    public get handshaked(): boolean { return this.sendingChain && this.receivingChain ? true : false; }

    public get publicKey(): Uint8Array { return this.keyPair.publicKey; }

    public get remoteKey(): Uint8Array | undefined { return this._remoteKey; }

    //public set remoteKey(key: Uint8Array) { this.setRemoteKey(key); }

    private setRemoteKey(key: Uint8Array): this {
        this._remoteKey = key;
        this.receivingChain = this.dhRatchet();
        this.previusCount = this.receivingCount;
        this.receivingCount = 0;
        this.keyPair = nacl.box.keyPair();
        this.sendingChain = this.dhRatchet();
        this.sendingCount = 0;
        return this;
    }

    private dhRatchet(info?: Uint8Array) {
        if (!this._remoteKey) throw new Error();
        const sharedKey = nacl.scalarMult(this.keyPair.secretKey, this._remoteKey);
        if (!this.rootKey)
            this.rootKey = this.rootKey = hash(sharedKey);
        const hashkey = hkdf(sharedKey, this.rootKey, info, DoubleRatchetSession.keyLength * 2);
        this.rootKey = hashkey.slice(0, DoubleRatchetSession.keyLength);
        return hashkey.slice(DoubleRatchetSession.keyLength);
    }

    private getSendingKey() {
        if (!this.sendingChain) throw new Error;
        const out = DoubleRatchetSessionConstructor.symmetricRatchet(this.sendingChain);
        this.sendingChain = out[0];
        this.sendingCount++;
        return out[1];
    }

    private getReceivingKey() {
        if (!this.receivingChain) throw new Error();
        const out = DoubleRatchetSessionConstructor.symmetricRatchet(this.receivingChain);
        this.receivingChain = out[0];
        this.receivingCount++;
        return out[1];
    }

    public encrypt(payload?: Uint8Array): EncryptedPayload | undefined {
        payload ??= new Uint8Array();
        try {
            const key = this.getSendingKey();
            if (this.sendingCount >= EncryptedPayloadConstructor.maxCount || this.previusCount >= EncryptedPayloadConstructor.maxCount) throw new Error();
            const nonce = nacl.randomBytes(EncryptedPayloadConstructor.nonceLength);
            const ciphertext = nacl.secretbox(payload, nonce, key);
            return new EncryptedPayloadConstructor(this.sendingCount, this.previusCount, this.keyPair.publicKey, nonce, ciphertext);
        } catch (error) {
            return undefined;
        }

    }

    public decrypt(payload?: Uint8Array | EncryptedPayload): Uint8Array | undefined {
        if (!payload) return undefined;
        try {
            const encrypted = EncryptedPayload.from(payload);
            const publicKey = encrypted.publicKey;
            if (!verifyUint8Array(publicKey, this._remoteKey)) {
                for (let i = this.receivingCount; i < encrypted.previous; i++) {
                    this.previusKeys.unshift(this.getReceivingKey());
                }
                this.setRemoteKey(publicKey);
            }
            let cleartext: Uint8Array | undefined;
            const count = encrypted.count;
            if (this.receivingCount < count) {
                for (let i = this.receivingCount; i < count; i++) {
                    this.previusKeys.unshift(this.getReceivingKey());
                }
                const key = this.previusKeys.shift();
                if (!key) return undefined;
                cleartext = nacl.secretbox.open(encrypted.ciphertext, encrypted.nonce, key) ?? undefined;
            } else {
                this.previusKeys.filter((key) => {
                    if (cleartext)
                        return true;
                    return !(cleartext = nacl.secretbox.open(encrypted.ciphertext, encrypted.nonce, key) ?? undefined);
                });
            }
            return cleartext;
        } catch (error) {
            return undefined;
        }
    }

    private static symmetricRatchet(chain: Uint8Array, salt?: Uint8Array, info?: Uint8Array) {
        const hash = hkdf(chain, salt, info, DoubleRatchetSession.keyLength * 2);
        return [new Uint8Array(hash.buffer, 0, DoubleRatchetSession.keyLength), new Uint8Array(hash.buffer, DoubleRatchetSession.keyLength)]
    }
}

export interface EncryptedPayload extends Uint8Array {
    //signed: boolean;

    readonly count: number;
    readonly previous: number;
    readonly publicKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;

    //setSigned(): this;
    encode(): Uint8Array;
    decode(): {
        count: number;
        previus: number;
        publicKey: string;
        nonce: string;
        ciphertext: string;
        signature?: string;
    };
    toString(): string;
    toJSON(): string;
}
export class EncryptedPayload implements EncryptedPayload {
    public static from(array: Uint8Array) {
        return new EncryptedPayloadConstructor(array) as EncryptedPayload;
    }
}

export class EncryptedPayloadConstructor extends Uint8Array implements EncryptedPayload {
    public static readonly signatureLength = nacl.sign.signatureLength;
    public static readonly secretKeyLength = nacl.box.secretKeyLength;
    public static readonly publicKeyLength = nacl.box.publicKeyLength;
    public static readonly keyLength = nacl.secretbox.keyLength;
    public static readonly nonceLength = nacl.secretbox.nonceLength;
    public static readonly maxCount = 65536 //32768;
    public static readonly countLength = 2;

    constructor(count: number | Uint8Array, previus: number | Uint8Array, publicKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array)
    constructor(encrypted: Uint8Array | EncryptedPayload)
    constructor(...arrays: Uint8Array[]) {
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
        })
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

    public get count() {
        let total = numberFromUint8Array(new Uint8Array(this.buffer, ...Offsets.count.get));
        total &= 2 ** (EncryptedPayloadConstructor.countLength * 8 - 1) - 1;
        return total;
    }

    public get previous() {
        return numberFromUint8Array(new Uint8Array(this.buffer, ...Offsets.previous.get));
    }

    public get publicKey() { return new Uint8Array(this.buffer, ...Offsets.publicKey.get); }

    public get nonce() { return new Uint8Array(this.buffer, ...Offsets.nonce.get); }

    public get ciphertext() { return new Uint8Array(this.buffer, Offsets.ciphertext.start); }

    public encode(): Uint8Array { return new Uint8Array(this); }

    public decode() {
        return {
            count: this.count,
            previus: this.previous,
            publicKey: encodeBase64(this.publicKey),
            nonce: encodeBase64(this.nonce),
            ciphertext: encodeUTF8(this.ciphertext),
            //signed: this.signed
        }
    }

    public toString(): string {
        return encodeUTF8(this);
    }

    public toJSON(): string {
        return JSON.stringify(this.decode());
    }

    public static from(array: Uint8Array) {
        return new EncryptedPayloadConstructor(array);
    }
}

class Offsets {

    private static set<T>(start: number, length: T) {
        class Offset<T> {
            readonly start: number;
            readonly end?: number;
            readonly length: T;

            constructor(start: number, length: T) {
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

    static readonly count = Offsets.set(0, EncryptedPayloadConstructor.countLength);

    static readonly previous = Offsets.set(Offsets.count.end!, EncryptedPayloadConstructor.countLength);

    static readonly publicKey = Offsets.set(Offsets.previous.end!, EncryptedPayloadConstructor.publicKeyLength);

    static readonly nonce = Offsets.set(Offsets.publicKey.end!, EncryptedPayloadConstructor.nonceLength);

    static readonly ciphertext = Offsets.set(Offsets.nonce.end!, undefined);

}
