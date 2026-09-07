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

package org.openhitls.crypto.jce.key;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import org.junit.Test;

public class ECKeyCodecTest {
    @Test
    public void testRequirePublicKeyMaterialRejectsNull() {
        expectMissingMaterial(null, "public");
    }

    @Test
    public void testRequirePrivateKeyMaterialRejectsEmpty() {
        expectMissingMaterial(new byte[0], "private");
    }

    @Test
    public void testRequireKeyMaterialReturnsEncodedBytes() {
        byte[] encoded = new byte[] { 1, 2, 3 };

        assertSame(encoded, ECKeyCodec.requireKeyMaterial(encoded, "public"));
    }

    private static void expectMissingMaterial(byte[] encoded, String keyType) {
        try {
            ECKeyCodec.requireKeyMaterial(encoded, keyType);
            fail("Expected missing key material failure");
        } catch (IllegalStateException expected) {
            assertEquals(
                    "Decoded EC " + keyType + " key does not contain key material",
                    expected.getMessage());
        }
    }
}
