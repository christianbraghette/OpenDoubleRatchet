export declare function encodeUTF8(array?: Uint8Array): string;
export declare function decodeUTF8(string?: string): Uint8Array;
export declare function encodeBase64(array?: Uint8Array): string;
export declare function decodeBase64(string?: string): Uint8Array;
export declare function numberFromUint8Array(array?: Uint8Array): number;
export declare function numberToUint8Array(number?: number, length?: number): Uint8Array;
export declare function createDoubleRatchetSession(remoteKey?: Uint8Array): DoubleRatchetSession;
export interface DoubleRatchetSession {
    readonly handshaked: boolean;
    readonly publicKey: Uint8Array;
    readonly remoteKey: Uint8Array | undefined;
    encrypt(payload: Uint8Array): EncryptedPayload | undefined;
    decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined;
}
export declare class DoubleRatchetSession {
    constructor(remoteKey?: Uint8Array);
    static readonly keyLength = 32;
}
export interface EncryptedPayload extends Uint8Array {
    readonly count: number;
    readonly previous: number;
    readonly publicKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
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
export declare class EncryptedPayload implements EncryptedPayload {
    static from(array: Uint8Array): EncryptedPayload;
}
