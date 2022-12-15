// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { SerializedCryptoKey, SFrameError, SFrameErrorType } from './Types.js';

export function generateIV(counter: Uint8Array, salt: SerializedCryptoKey): Uint8Array {
    try {
        const saltLength = salt.byteLength;
        const saltArray = new Uint8Array(salt);
        const counterLength = counter.length;
        const iv = new Uint8Array(saltLength);
        const view = new DataView(iv.buffer);

        for (let i = 0; i < counterLength; i++) {
            view.setUint8(saltLength - counterLength + i, counter[i]);
        }

        //Xor with salt key
        for (let i = 0; i < iv.byteLength; ++i) {
            view.setUint8(i, iv[i] ^ saltArray[i]);
        }
        return iv;
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : '';
        throw new SFrameError(SFrameErrorType.InitializationVectorError, 'IV: ' + message);
    }
}
