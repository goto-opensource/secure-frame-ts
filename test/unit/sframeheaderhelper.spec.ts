// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { assert } from 'chai';

import {
    generateSFrameHeader,
    parseSFrameHeader,
    SFRAME_HEADER_MAXKEYID,
    SFrameHeader,
} from '../../src/SFrameHeader.js';
import * as Utils from '../../src/Utils.js';

// Serialize header for comparison
const serialize = (header: SFrameHeader) =>
    Utils.toHex(header.data) +
    ',k:' +
    header.keyId.toString(16) +
    ',c:' +
    header.counter.toString(16);
const serializeBin = (header: SFrameHeader) =>
    Utils.toBin(header.data) + ',k:' + header.keyId.toString() + ',c:' + header.counter.toString();

describe('SFrame Header', () => {
    describe('parse', () => {
        const assertEqParseBin = (input: string, expected: string) =>
            assert.equal(serializeBin(parseSFrameHeader(Utils.fromBin(input))), expected);
        const assertEqParseHex = (from: string, expected: string) =>
            assert.equal(serialize(parseSFrameHeader(Utils.fromHex(from))), expected);

        it('basic key', () => {
            /*   RLEN XKID|CTR (L=1)|Frame content       */
            assertEqParseBin(
                '0000 0000 0000 0000 1100 1010 1100 1010',
                '0000 0000 0000 0000,k:0,c:0'
            );
            assertEqParseBin(
                '0000 0010 0000 0000 1100 1010 1100 1010',
                '0000 0010 0000 0000,k:2,c:0'
            );
            assertEqParseBin(
                '0000 0110 0000 0001 1100 1010 1100 1010',
                '0000 0110 0000 0001,k:6,c:1'
            );
            /*   RLEN XKID|CTR (L=3)                    |*/
            assertEqParseBin(
                '0010 0111 0000 0000 0000 0000 1000 1100',
                '0010 0111 0000 0000 0000 0000 1000 1100,k:7,c:140'
            );

            // first two: metadata byte, then counter (vary length)

            assertEqParseHex('0000caca', '0000,k:0,c:0');
            assertEqParseHex('0001caca', '0001,k:0,c:1');
            assertEqParseHex('0101caca', '0101,k:1,c:1');
            assertEqParseHex('0201caca', '0201,k:2,c:1');
            assertEqParseHex('0301caca', '0301,k:3,c:1');

            assertEqParseHex('30ff000000caca', '30ff000000,k:0,c:ff000000');
            assertEqParseHex('30ff010203caca', '30ff010203,k:0,c:ff010203');
            assertEqParseHex('31ff000000caca', '31ff000000,k:1,c:ff000000');
            assertEqParseHex('31ff010203caca', '31ff010203,k:1,c:ff010203');
        });

        it('extended key', () => {
            /*   RLEN XKLN|KID (L=1)|CTR (L=3)                    |*/
            assertEqParseBin(
                '0010 1000 1000 1101 0000 0000 0000 0000 1000 1100',
                '0010 1000 1000 1101 0000 0000 0000 0000 1000 1100,k:141,c:140'
            );
            /*   RLEN XKLN|KID (L=3)                    |CTR (L=2)          |*/
            assertEqParseBin(
                '0001 1010 0000 0000 0000 0000 1000 1101 0000 0000 1000 1100',
                '0001 1010 0000 0000 0000 0000 1000 1101 0000 0000 1000 1100,k:141,c:140'
            );

            // first two: metadata byte, then KID (vary length) and counter (vary length)

            assertEqParseHex('080800caca', '080800,k:8,c:0');
            assertEqParseHex('080801caca', '080801,k:8,c:1');

            assertEqParseHex('09010000caca', '09010000,k:100,c:0');
            assertEqParseHex('09010101caca', '09010101,k:101,c:1');

            assertEqParseHex('0abbccddffcaca', '0abbccddff,k:bbccdd,c:ff');
        });
    });

    describe('generate', () => {
        const assertEqGenBin = (keyId: number, counter: number, expected: string) => {
            return assert.equal(Utils.toBin(generateSFrameHeader(keyId, counter).data), expected);
        };
        const assertEqGenHex = (keyId: number, counter: number, expected: string) => {
            return assert.equal(Utils.toHex(generateSFrameHeader(keyId, counter).data), expected);
        };

        it('basic key', () => {
            // LEN=0
            /*                    RLEN XKID|CTR (L=1)| */
            assertEqGenBin(0, 0, '0000 0000 0000 0000');
            assertEqGenBin(0, 1, '0000 0000 0000 0001');
            assertEqGenBin(1, 0, '0000 0001 0000 0000');
            assertEqGenBin(1, 1, '0000 0001 0000 0001');
            assertEqGenBin(2, 0, '0000 0010 0000 0000');
            assertEqGenBin(3, 1, '0000 0011 0000 0001');
            assertEqGenBin(7, 255, '0000 0111 1111 1111');

            // LEN=1
            /*                      RLEN XKID|CTR (L=2)          | */
            assertEqGenBin(0, 256, '0001 0000 0000 0001 0000 0000');
            assertEqGenBin(7, 256, '0001 0111 0000 0001 0000 0000');
            assertEqGenBin(7, 257, '0001 0111 0000 0001 0000 0001');

            // LEN=3 (4 byte ctr)
            assertEqGenHex(0, 0xff010203, '30ff010203');
            assertEqGenHex(7, 0xff010203, '37ff010203');

            // LEN=6 (7 byte ctr)
            assertEqGenHex(0, 0x11a2a3a4a5a6a7, '6011a2a3a4a5a6a7');
            assertEqGenHex(7, 0x11a2a3a4a5a6a7, '6711a2a3a4a5a6a7');
        });

        it('extended key', () => {
            // x, KLEN=0, LEN=0
            /*                    RLEN XKID|KID (L=1)|CTR (L=1)| */
            assertEqGenBin(8, 0, '0000 1000 0000 1000 0000 0000');
            assertEqGenBin(8, 1, '0000 1000 0000 1000 0000 0001');

            // x, KLEN=1, LEN=0
            /*                      RLEN XKID|KID (L=2)          |CTR (L=1)| */
            assertEqGenBin(256, 0, '0000 1001 0000 0001 0000 0000 0000 0000');
            assertEqGenBin(256, 1, '0000 1001 0000 0001 0000 0000 0000 0001');

            // x, KLEN=2, LEN=0
            assertEqGenHex(0xbbccdd, 255, '0abbccddff');
            // x, KLEN=3, LEN=1
            assertEqGenHex(0xbbccddee, 256, '1bbbccddee0100');
            // x, KLEN=6, LEN=6
            assertEqGenHex(0x11b2b3b4b5b6b7, 0x11a2a3a4a5a6a7, '6e11b2b3b4b5b6b711a2a3a4a5a6a7');

            assertEqGenHex(
                SFRAME_HEADER_MAXKEYID,
                0,
                '0e' + SFRAME_HEADER_MAXKEYID.toString(16) + '00'
            );
        });
        // it("generate invalid",function(test){
        // 	//This should be invalid
        // 	test.throws(() => Header.generate(false,-1,0));
        // 	test.throws(() => Header.generate(false,Header.MaxKeyId+1,0));
        // 	test.end();
        // });
    });
});
