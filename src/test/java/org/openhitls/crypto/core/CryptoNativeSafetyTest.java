package org.openhitls.crypto.core;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;

import static org.junit.Assert.assertThrows;

public class CryptoNativeSafetyTest extends BaseTest {
    @Test
    public void testDigestUpdateRejectsInvalidNativeRanges() {
        long context = CryptoNative.messageDigestInit("SHA-256");
        byte[] data = new byte[4];
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.messageDigestUpdate(context, data, -1, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.messageDigestUpdate(context, data, 0, -1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.messageDigestUpdate(context, data, 2, 3));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.messageDigestUpdate(context, data, Integer.MAX_VALUE, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.messageDigestUpdate(context, data, 1, Integer.MAX_VALUE));
        } finally {
            CryptoNative.messageDigestFree(context);
        }
    }

    @Test
    public void testHmacUpdateRejectsInvalidNativeRanges() {
        long context = CryptoNative.hmacInit("HMACSHA256", new byte[16]);
        byte[] data = new byte[4];
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.hmacUpdate(context, data, -1, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.hmacUpdate(context, data, 0, -1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.hmacUpdate(context, data, 2, 3));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.hmacUpdate(context, data, Integer.MAX_VALUE, 1));
            assertThrows(IllegalArgumentException.class,
                    () -> CryptoNative.hmacUpdate(context, data, 1, Integer.MAX_VALUE));
        } finally {
            CryptoNative.hmacFree(context);
        }
    }

}
