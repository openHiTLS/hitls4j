package org.openhitls.crypto.core.hash;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.CryptoNative;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class MessageDigestImplTest extends BaseTest {
    @Test
    public void testUpdateRejectsOverflowingRanges() {
        assertInvalidUpdateRange(Integer.MAX_VALUE, 1);
        assertInvalidUpdateRange(1, Integer.MAX_VALUE);
    }

    @Test
    public void testNativeUpdateRejectsOverflowingRanges() {
        assertInvalidNativeUpdateRange(Integer.MAX_VALUE, 1);
        assertInvalidNativeUpdateRange(1, Integer.MAX_VALUE);
    }

    @Test
    public void testUpdateWithValidRangeHashesOnlyRequestedBytes() throws Exception {
        byte[] input = "xxabcxx".getBytes(StandardCharsets.US_ASCII);
        MessageDigestImpl digest = new MessageDigestImpl("SHA-256");

        digest.update(input, 2, 3);

        assertArrayEquals(hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                digest.doFinal());
    }

    private void assertInvalidUpdateRange(int offset, int length) {
        MessageDigestImpl digest = new MessageDigestImpl("SHA-256");
        try {
            digest.update(new byte[4], offset, length);
            fail("Expected MessageDigestImpl.update to reject invalid range");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private void assertInvalidNativeUpdateRange(int offset, int length) {
        ExposedMessageDigestImpl digest = new ExposedMessageDigestImpl("SHA-256");
        try {
            CryptoNative.messageDigestUpdate(digest.context(), new byte[4], offset, length);
            fail("Expected native messageDigestUpdate to reject invalid range");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static byte[] hex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return bytes;
    }

    private static final class ExposedMessageDigestImpl extends MessageDigestImpl {
        private ExposedMessageDigestImpl(String algorithm) {
            super(algorithm);
        }

        private long context() {
            return nativeContext;
        }
    }
}
