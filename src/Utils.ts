// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

export function dec2bin(dec: number): string {
    return (dec >>> 0).toString(2);
}

export function bin2dec(bin: string): number {
    return parseInt(bin, 2);
}

export function toBin(buffer: ArrayBuffer | Uint8Array): string {
    const s = Array.prototype.map
        .call(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer), (x) =>
            x.toString(2).padStart(8, '0')
        )
        .join('');
    return [...s].map((d, i) => (i > 0 && i % 4 == 0 ? ' ' + d : d)).join(''); // Add space every 4 chars.
}

export function fromBin(str: string): Uint8Array {
    const bytes = [];
    str = str.replace(/ /g, '');
    const sliceLength = 8; // 2^8 -> 1 byte
    for (let i = 0; i < str.length / sliceLength; ++i) {
        const n = parseInt(str.substring(i * sliceLength, (i + 1) * sliceLength), 2);
        bytes.push(n);
    }
    return new Uint8Array(bytes);
}

export function toHex(buffer: ArrayBuffer | Uint8Array): string {
    return Array.prototype.map
        .call(buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer), (x) =>
            x.toString(16).padStart(2, '0')
        )
        .join('');
}

export function fromHex(str: string): Uint8Array {
    const bytes = [];
    const sliceLength = 2; // 16^2 -> 1 byte
    for (let i = 0; i < str.length / sliceLength; ++i) {
        const n = parseInt(str.substring(i * sliceLength, (i + 1) * sliceLength), 16);
        bytes.push(n);
    }
    return new Uint8Array(bytes);
}

export function equals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.byteLength != b.byteLength) return false;
    for (let i = 0; i != a.byteLength; i++) if (a[i] != b[i]) return false;
    return true;
}
