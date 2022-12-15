// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SerializedCryptoKey } from './Types';

export enum CipherSuiteVariant {
    AES_CM_128_HMAC_SHA256_8 = 1,
    AES_CM_128_HMAC_SHA256_4 = 2,
    AES_GCM_128_SHA256 = 3,
    AES_GCM_256_SHA512 = 4,
}

export type CipherSuiteConfig = {
    algorithm: string;
    keyAlgorithm: string;
    hashAlgorithm: string;
    /** The output size of the Extract() function in bytes. */
    nH: number;
    /** The length in bytes of the cipher key for this algorithm. */
    nK: number;
    /** The length in bytes of a nonce for this algorithm. */
    nN: number;
    /** The length in bytes of the authentication tag for this
         algorithm. */
    nT: number;
};

export class CipherSuite {
    constructor(
        public readonly config: CipherSuiteConfig,
        public readonly baseKey: CryptoKey,
        public readonly encryptionKey: CryptoKey,
        public readonly saltKey: SerializedCryptoKey,
        public readonly authKey: CryptoKey
    ) {}

    public async deriveEncryptionKeyBits(): Promise<Uint8Array> {
        return this.deriveBits('key', this.config.nK);
    }

    public async deriveSaltBits(): Promise<Uint8Array> {
        return this.deriveBits('salt', this.config.nN);
    }

    private async deriveBits(info: string, size: number): Promise<Uint8Array> {
        return new Uint8Array(
            await crypto.subtle.deriveBits(
                {
                    name: this.config.keyAlgorithm,
                    hash: this.config.hashAlgorithm,
                    salt: new TextEncoder().encode('SFrame10'),
                    info: new TextEncoder().encode(info),
                },
                this.baseKey,
                size * 8 // bits
            )
        );
    }
}

function getCipherSuiteConfig(variant: CipherSuiteVariant): CipherSuiteConfig | undefined {
    const defs = new Map<CipherSuiteVariant, CipherSuiteConfig>([
        [
            CipherSuiteVariant.AES_CM_128_HMAC_SHA256_8,
            {
                algorithm: 'AES-CTR',
                keyAlgorithm: 'HKDF',
                hashAlgorithm: 'SHA-256',
                nH: 32,
                nK: 16,
                nN: 12,
                nT: 8,
            },
        ],
        [
            CipherSuiteVariant.AES_CM_128_HMAC_SHA256_4,
            {
                algorithm: 'AES-CTR',
                keyAlgorithm: 'HKDF',
                hashAlgorithm: 'SHA-256',
                nH: 32,
                nK: 16,
                nN: 12,
                nT: 4,
            },
        ],
        [
            CipherSuiteVariant.AES_GCM_128_SHA256,
            {
                algorithm: 'AES-GCM',
                keyAlgorithm: 'HKDF',
                hashAlgorithm: 'SHA-256',
                nH: 32,
                nK: 16,
                nN: 12,
                nT: 8,
            },
        ],
        [
            CipherSuiteVariant.AES_GCM_256_SHA512,
            {
                algorithm: 'AES-GCM',
                keyAlgorithm: 'HKDF',
                hashAlgorithm: 'SHA-512',
                nH: 64,
                nK: 32,
                nN: 12,
                nT: 16, // max tag length against forgery attack
            },
        ],
    ]);
    return defs.get(variant);
}

export async function createCipherSuite(
    cipherSuite: CipherSuiteVariant,
    keyMaterial: SerializedCryptoKey
) {
    const config = getCipherSuiteConfig(cipherSuite);
    if (!config) {
        throw new Error('no config found for cipher suite variant');
    }

    const key = await crypto.subtle.importKey('raw', keyMaterial, config.keyAlgorithm, false, [
        'deriveBits',
        'deriveKey',
    ]);

    //Get encryption key
    const encryptionKey = await crypto.subtle.deriveKey(
        {
            name: config.keyAlgorithm,
            hash: config.hashAlgorithm,
            salt: new TextEncoder().encode('SFrame10'),
            info: new TextEncoder().encode('key'),
        },
        key,
        {
            name: config.algorithm,
            length: config.nK * 8, // bits
        },
        false,
        ['encrypt', 'decrypt']
    );

    const saltKey = await crypto.subtle.deriveBits(
        {
            name: config.keyAlgorithm,
            hash: config.hashAlgorithm,
            salt: new TextEncoder().encode('SFrame10'),
            info: new TextEncoder().encode('salt'),
        },
        key,
        config.nN * 8 // bits
    );

    //Get authentication key
    const authKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('SFrame10'),
            info: new TextEncoder().encode('auth'),
        },
        key,
        {
            name: 'HMAC',
            hash: 'SHA-256',
            length: config.nK * 8, // bits
        },
        false,
        ['sign', 'verify']
    );

    return new CipherSuite(config, key, encryptionKey, saltKey, authKey);
}
