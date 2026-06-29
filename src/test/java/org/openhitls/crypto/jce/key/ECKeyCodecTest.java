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
