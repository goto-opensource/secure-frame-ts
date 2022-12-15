// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

/*
    Since each endpoint can send multiple media layers, each frame will have a unique frame counter
    that will be used to derive the encryption IV. The frame counter must be unique and monotonically
    increasing to avoid IV reuse.

    Both the frame counter and the key id are encoded in a variable length format to decrease the overhead.
    The length is up to 8 bytes and is represented in 3 bits in the SFrame header:
    000 represents a length of 1, 001 a length of 2...
    The first byte in the SFrame header is fixed and contains the header metadata with the following format:

     0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+
    |R|LEN  |X|  K  |
    +-+-+-+-+-+-+-+-+
    SFrame header metadata
 
    Reserved (R): 1 bit This field MUST be set to zero on sending, and MUST be ignored by receivers.
    Counter Length (LEN): 3 bits This field indicates the length of the CTR fields in bytes (1-8).
    Extended Key Id Flag (X): 1 bit Indicates if the key field contains the key id or the key length.
    Key or Key Length: 3 bits This field contains the key id (KID) if the X flag is set to 0, or the key length (KLEN) if set to 1.
 
    If X flag is 0 then the KID is in the range of 0-7 and the frame counter (CTR) is found in the next LEN bytes:
     0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+---------------------------------+
    |R|LEN  |0| KID |    CTR... (length=LEN)          |
    +-+-+-+-+-+-+-+-+---------------------------------+

    Frame counter byte length (LEN): 3bits The frame counter length in bytes (1-8).
    Key id (KID): 3 bits The key id (0-7).
    Frame counter (CTR): (Variable length) Frame counter value up to 8 bytes long.

    If X flag is 1 then KLEN is the length of the key (KID), that is found after the SFrame header metadata byte.
    After the key id (KID), the frame counter (CTR) will be found in the next LEN bytes:

     0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
    |R|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
    +-+-+-+-+-+-+-+-+---------------------------+---------------------------+

    Frame counter byte length (LEN): 3bits The frame counter length in bytes (1-8).
    Key length (KLEN): 3 bits The key length in bytes (1-8).
    Key id (KID): (Variable length) The key id value up to 8 bytes long.
    Frame counter (CTR): (Variable length) Frame counter value up to 8 bytes long.
*/

import { SFrameError, SFrameErrorType } from './Types.js';

export type SFrameHeader = {
    data: Uint8Array;
    keyId: number;
    counter: number;
    rawCounter: Uint8Array;
};

// According to spec it would be 2^64-1, but 0xffffffffffffffff is not available before es2020.
export const SFRAME_HEADER_MAXKEYID = Number.MAX_SAFE_INTEGER;
const lengthAdjustment = 1; // 0 means a length of 1, 1 a length of 2 etc.

export function parseSFrameHeader(buffer: ArrayBuffer): SFrameHeader {
    const view = new Uint8Array(buffer);

    const metadata = view[0]; // first byte = metadata
    const ctrLEN = (metadata >> 4) & 0x07; // 111
    const isExtendedKey = !!(metadata & 0x08); // 0000 1000
    const keyLenOrKeyId = metadata & 0x07; // 0000 0111; KLEN, KID

    // Get key id
    let keyId = 0;
    let headerLength = 0;
    let ctrStartIdx = 0;
    const staticHeaderLength = 1;
    const frameCounterLength = ctrLEN + lengthAdjustment; // 0 means a length of 1, 1 a length of 2 etc.

    if (isExtendedKey) {
        const extendedKeyLength = keyLenOrKeyId + lengthAdjustment; // 0 means a length of 1, 1 a length of 2 etc.
        for (let i = 0; i < extendedKeyLength; i++) {
            keyId = keyId * 256 + view[i + staticHeaderLength];
        }
        headerLength = extendedKeyLength + frameCounterLength;
        ctrStartIdx = staticHeaderLength + extendedKeyLength;
    } else {
        keyId = keyLenOrKeyId;
        headerLength = frameCounterLength;
        ctrStartIdx = staticHeaderLength;
    }

    let counter = 0;
    for (let i = 0; i < frameCounterLength; i++) {
        counter = counter * 256 + view[ctrStartIdx + i];
    }

    const rawCounter = view.slice(ctrStartIdx, ctrStartIdx + frameCounterLength);

    // Header buffer view
    const header = {
        data: view.subarray(0, headerLength + 1),
        keyId: keyId,
        counter: counter,
        rawCounter: rawCounter,
    };

    return header;
}

export function generateSFrameHeader(keyId: number, counter: number): SFrameHeader {
    checkSFrameHeaderKeyId(keyId);

    const calculateKLENorLEN = (i: number): number =>
        i ? parseInt((Math.log(i) / Math.log(256)).toString()) : 0; // 0 means a length of 1, 1 a length of 2 etc.

    const isExtendedKey = keyId > 7;
    const keyLenOrKeyId = isExtendedKey ? calculateKLENorLEN(keyId) : keyId;
    const ctrLEN = calculateKLENorLEN(counter);

    if (ctrLEN > 7) {
        // 7 means a length of 8
        throw new Error('The length of the CTR fields in bytes must be between 1-8');
    }

    // All lengths in bytes.
    const staticHeaderLength = 1;
    const extendedKeyLength = keyLenOrKeyId + lengthAdjustment; // 0 means a length of 1 byte, 1 a length of 2 etc.
    const frameCounterLength = ctrLEN + lengthAdjustment; // 0 means a length of 1 byte, 1 a length of 2 etc.
    const headerDataLength = isExtendedKey
        ? staticHeaderLength + extendedKeyLength + frameCounterLength
        : staticHeaderLength + frameCounterLength;
    const headerData = new Uint8Array(headerDataLength);

    // Set metadata header
    headerData[0] = 0x00; // 0000 0000 leading reserve bit is always 0
    headerData[0] = (headerData[0] << 3) | (ctrLEN & 0x07); // 111
    headerData[0] = (headerData[0] << 1) | (isExtendedKey ? 0x01 : 0x00);
    headerData[0] = (headerData[0] << 3) | (keyLenOrKeyId & 0x07); // 111

    const toUint8ArrayViaI64 = (input: number, length: number): Uint8Array => {
        const i64 = BigInt(input);
        const a64 = new BigUint64Array([i64]);
        return new Uint8Array(a64.buffer).slice(0, length).reverse();
    };
    const addToHeaderViaI64 = (leftOffset: number, input: number, length: number) => {
        const a8 = toUint8ArrayViaI64(input, length);
        for (let i = 0; i < length; ++i) {
            headerData[leftOffset + i] = a8[i];
        }
    };

    // Append extended key id byte by byte.
    if (isExtendedKey) {
        addToHeaderViaI64(staticHeaderLength, keyId, extendedKeyLength);
    }

    // Append frame counter byte by byte.
    const ctrStartIdx = isExtendedKey ? extendedKeyLength + 1 : 1;

    addToHeaderViaI64(ctrStartIdx, counter, frameCounterLength);

    return {
        data: headerData,
        keyId: keyId,
        counter: counter,
        rawCounter: headerData.slice(ctrStartIdx, ctrStartIdx + frameCounterLength),
    };
}

export function checkSFrameHeaderKeyId(keyId: number): void {
    if (keyId < 0) {
        throw new SFrameError(SFrameErrorType.InvalidHeaderKey, 'keyId must be positive');
    }
    if (keyId > SFRAME_HEADER_MAXKEYID) {
        throw new SFrameError(
            SFrameErrorType.InvalidHeaderKey,
            `keyId must be 8 bytes long at most according to spec, but in Javascript the max allowed keysize is ${SFRAME_HEADER_MAXKEYID}`
        );
    }
}
