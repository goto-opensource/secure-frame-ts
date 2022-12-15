// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

/* eslint-disable @typescript-eslint/no-explicit-any */
import { webcrypto } from 'crypto';

export function attachWebCryptoToGlobal() {
    (global as any).window = (global as any).window || global;
    (global as any).window.crypto = webcrypto;
}
