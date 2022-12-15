// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

import { assert } from 'chai';
import { generateIV } from '../../src/IV.js';
import * as Utils from '../../src/Utils.js';

describe('IV', () => {
    const prepareTest = (salt: string) => {
        return (counter: string, expectatedNonce: string) => {
            const nonce = generateIV(Utils.fromHex(counter), Utils.fromHex(salt));
            assert(Utils.toHex(nonce), expectatedNonce);
        };
    };

    it('draft 0.3 compliance', () => {
        // tests for ciphersuite 1
        const test1 = prepareTest('42d662fbad5cd81eb3aad79a');
        test1('0', '42d662fbad5cd81eb3aad79a');
        test1('1', '42d662fbad5cd81eb3aad79b');
        test1('2', '42d662fbad5cd81eb3aad798');
        test1('aa', '42d662fbad5cd81eb3aad730');
        test1('aaaa', '42d662fbad5cd81eb3aa7d30');
        test1('ffffffffffffff', '42d662fbada327e14c552865');

        //tests for ciphersuite 2
        const test2 = prepareTest('77fbf5f1d82c73f6d2b353c9');
        test2('0', '77fbf5f1d82c73f6d2b353c9');
        test2('1', '77fbf5f1d82c73f6d2b353c8');
        test2('2', '77fbf5f1d82c73f6d2b353cb');
        test2('aa', '77fbf5f1d82c73f6d2b35363');
        test2('aaaa', '77fbf5f1d82c73f6d2b3f963');
        test2('ffffffffffffff', '77fbf5f1d8d38c092d4cac36');

        //tests for ciphersuite 3
        const test3 = prepareTest('a80478b3f6fba19983d540d5');
        test3('0', 'a80478b3f6fba19983d540d5');
        test3('1', 'a80478b3f6fba19983d540d4');
        test3('2', 'a80478b3f6fba19983d540d7');
        test3('aa', 'a80478b3f6fba19983d5407f');
        test3('aaaa', 'a80478b3f6fba19983d5ea7f');
        test3('ffffffffffffff', 'a80478b3f6045e667c2abf2a');

        //tests for ciphersuite 4
        const test4 = prepareTest('31ed26f90a072e6aee646298');
        test4('0', '31ed26f90a072e6aee646298');
        test4('1', '31ed26f90a072e6aee646299');
        test4('2', '31ed26f90a072e6aee64629a');
        test4('aa', '31ed26f90a072e6aee646232');
        test4('aaaa', '31ed26f90a072e6aee64c832');
        test4('ffffffffffffff', '31ed26f90af8d195119b9d67');
    });
});
