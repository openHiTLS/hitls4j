package org.openhitls.crypto.core.symmetric;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.CryptoNative;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

public class SymmetricCipherNativeTest extends BaseTest {
    @Test
    public void testSetAADRejectsInvalidNativeRanges() {
        long context = newGcmContext();
        byte[] aad = new byte[4];
        try {
            assertInvalidAADRange(context, aad, -1, 1);
            assertInvalidAADRange(context, aad, 0, -1);
            assertInvalidAADRange(context, aad, aad.length + 1, 0);
            assertInvalidAADRange(context, aad, aad.length, 1);
            assertInvalidAADRange(context, aad, 2, 3);
            assertInvalidAADRange(context, aad, Integer.MAX_VALUE, 1);
            assertInvalidAADRange(context, aad, 1, Integer.MAX_VALUE);
        } finally {
            CryptoNative.symmetricCipherFree(context);
        }
    }

    @Test
    public void testSetAADAcceptsValidNativeRanges() {
        long context = newGcmContext();
        try {
            byte[] aad = new byte[] {1, 2, 3, 4};
            CryptoNative.symmetricCipherSetAAD(context, aad, aad.length, 0);
            CryptoNative.symmetricCipherSetAAD(context, aad, 1, 2);
        } finally {
            CryptoNative.symmetricCipherFree(context);
        }
    }

    @Test
    public void testUpdateRejectsInvalidNativeBuffers() {
        long context = newGcmContext();
        byte[] input = new byte[16];
        byte[] output = new byte[32];
        int[] outLen = new int[1];
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, -1, 1, output, 0, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 0, -1, output, 0, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 8, 9, output, 0, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 1, Integer.MAX_VALUE,
                            output, 0, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 0, input.length,
                            output, -1, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 0, input.length,
                            output, output.length + 1, outLen));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, input, 0, input.length,
                            output, 0, new int[0]));
        } finally {
            CryptoNative.symmetricCipherFree(context);
        }
    }

    @Test
    public void testUpdateUsesActualOutputCapacity() {
        long context = newGcmContext();
        try {
            assertThrows(IllegalStateException.class,
                    () -> CryptoNative.symmetricCipherUpdate(context, new byte[16], 0, 16,
                            new byte[1], 0, new int[1]));
        } finally {
            CryptoNative.symmetricCipherFree(context);
        }
    }

    private static long newGcmContext() {
        return CryptoNative.symmetricCipherInit(
                "AES", "GCM", new byte[16], new byte[16], SymmetricCipherImpl.MODE_ENCRYPT);
    }

    private static void assertInvalidAADRange(long context, byte[] aad, int offset, int len) {
        try {
            CryptoNative.symmetricCipherSetAAD(context, aad, offset, len);
            fail("Expected native symmetricCipherSetAAD to reject invalid range");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }
}
