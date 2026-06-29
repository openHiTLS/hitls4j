package org.openhitls.crypto.jce.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.security.SignatureException;
import org.junit.Test;

public class SignerBufferTest {
    @Test
    public void testAppendZeroizesPreviousBuffer() throws Exception {
        byte[] oldBuffer = new byte[] { 1, 2, 3 };
        byte[] input = new byte[] { 4, 5 };

        byte[] appended = SignerBuffer.append(oldBuffer, input, 0, input.length);

        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5 }, appended);
        assertArrayEquals(new byte[] { 0, 0, 0 }, oldBuffer);
    }

    @Test
    public void testAppendCreatesInitialBuffer() throws Exception {
        byte[] input = new byte[] { 1, 2, 3, 4 };

        byte[] appended = SignerBuffer.append(null, input, 1, 2);

        assertArrayEquals(new byte[] { 2, 3 }, appended);
    }

    @Test
    public void testAppendRejectsInvalidInputRanges() {
        expectInvalidAppend(null, 0, 1);
        expectInvalidAppend(new byte[] { 1, 2 }, -1, 1);
        expectInvalidAppend(new byte[] { 1, 2 }, 0, -1);
        expectInvalidAppend(new byte[] { 1, 2 }, 2, 1);
        expectInvalidAppend(new byte[] { 1, 2 }, 1, 2);
    }

    @Test
    public void testValidateAdditionalLengthRejectsOverflow() {
        try {
            SignerBuffer.validateAdditionalLength(Integer.MAX_VALUE, 1);
            fail("Expected overflowing update length to be rejected");
        } catch (SignatureException expected) {
            // Expected.
        }
    }

    @Test
    public void testEcdsaEngineUpdateWrapsInvalidInputRanges() {
        ECDSASigner signer = new ECDSASigner.SHA256withECDSA();

        try {
            signer.engineUpdate(new byte[] { 1, 2 }, -1, 1);
            fail("Expected invalid ECDSA update parameters to be rejected");
        } catch (SignatureException expected) {
            // Expected.
        }
    }

    @Test
    public void testClearZeroizesBuffer() {
        byte[] buffer = new byte[] { 9, 8, 7 };

        assertNull(SignerBuffer.clear(buffer));
        assertArrayEquals(new byte[] { 0, 0, 0 }, buffer);
    }

    @Test
    public void testResizeZeroizesPreviousBuffer() {
        byte[] oldBuffer = new byte[] { 1, 2, 3 };

        byte[] resized = SignerBuffer.resize(oldBuffer, 5);

        assertArrayEquals(new byte[] { 1, 2, 3, 0, 0 }, resized);
        assertArrayEquals(new byte[] { 0, 0, 0 }, oldBuffer);
    }

    private static void expectInvalidAppend(byte[] input, int offset, int length) {
        try {
            SignerBuffer.append(null, input, offset, length);
            fail("Expected invalid update parameters to be rejected");
        } catch (SignatureException expected) {
            // Expected.
        }
    }
}
