/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.crypto.core.pqc;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.CryptoNative;

import static org.junit.Assert.fail;

public class KEMNativeNullInputTest extends BaseTest {
    @Test
    public void testFrodoKemNativeRejectsNullReferences() {
        expectIllegalArgument(() -> CryptoNative.frodoKemCreateContext(null));
        expectIllegalArgument(() -> CryptoNative.frodoKemGenerateKeyPair(0, null));
        expectIllegalArgument(() -> CryptoNative.frodoKemDecapsulate(0, null));
    }

    @Test
    public void testMcElieceNativeRejectsNullReferences() {
        expectIllegalArgument(() -> CryptoNative.mcelieceCreateContext(null));
        expectIllegalArgument(() -> CryptoNative.mcelieceGenerateKeyPair(0, null));
        expectIllegalArgument(() -> CryptoNative.mcelieceDecapsulate(0, null));
    }

    @Test
    public void testFrodoKemNativeRejectsInvalidContext() {
        expectIllegalState(() -> CryptoNative.frodoKemGenerateKeyPair(0, "FrodoKEM-640-SHAKE"));
        expectIllegalState(() -> CryptoNative.frodoKemSetKeys(0, new byte[1], null));
        expectIllegalState(() -> CryptoNative.frodoKemEncapsulate(0));
        expectIllegalState(() -> CryptoNative.frodoKemDecapsulate(0, new byte[1]));
    }

    @Test
    public void testMcElieceNativeRejectsInvalidContext() {
        expectIllegalState(() -> CryptoNative.mcelieceGenerateKeyPair(0, "McEliece-6688128f"));
        expectIllegalState(() -> CryptoNative.mcelieceSetKeys(0, new byte[1], null));
        expectIllegalState(() -> CryptoNative.mcelieceEncapsulate(0));
        expectIllegalState(() -> CryptoNative.mcelieceDecapsulate(0, new byte[1]));
    }

    private static void expectIllegalArgument(NativeCall call) {
        try {
            call.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        } catch (Throwable actual) {
            fail("Expected IllegalArgumentException but got " + actual);
        }
    }

    private static void expectIllegalState(NativeCall call) {
        try {
            call.run();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException expected) {
            // Expected.
        } catch (Throwable actual) {
            fail("Expected IllegalStateException but got " + actual);
        }
    }

    private interface NativeCall {
        void run();
    }
}
