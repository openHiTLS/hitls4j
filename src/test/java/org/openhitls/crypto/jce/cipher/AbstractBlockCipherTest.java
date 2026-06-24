package org.openhitls.crypto.jce.cipher;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.symmetric.SymmetricCipherImpl;

public class AbstractBlockCipherTest extends BaseTest {
    private static final byte[] SM4_KEY = new byte[] {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    private static final byte[] IV = new byte[] {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    @Test
    public void testStreamResetFailureDoesNotReplaceDoFinalFailure() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        cipher.replaceCipher(new RuntimeExceptionOnUpdateCipher());
        cipher.replaceResetKey(new byte[15]);

        try {
            cipher.doFinalWithValidInput();
            fail("Expected doFinal failure");
        } catch (IllegalStateException expected) {
            assertEquals("Error during final operation", expected.getMessage());
            assertNotNull(expected.getCause());
            assertTrue(expected.getCause().getMessage().contains("primary failure"));
            assertEquals(1, expected.getSuppressed().length);
            assertTrue(expected.getSuppressed()[0].getMessage().contains("Key must be 16 bytes"));
        }
    }

    @Test
    public void testStreamResetFailureDoesNotReplaceDoFinalError() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        cipher.replaceCipher(new ErrorOnUpdateCipher());
        cipher.replaceResetKey(new byte[15]);

        try {
            cipher.doFinalWithValidInput();
            fail("Expected doFinal error");
        } catch (AssertionError expected) {
            assertEquals("primary failure", expected.getMessage());
            assertEquals(1, expected.getSuppressed().length);
            assertTrue(expected.getSuppressed()[0].getMessage().contains("Key must be 16 bytes"));
        }
    }

    @Test
    public void testStreamResetCloseFailureDoesNotReplaceSuccessfulDoFinal() throws Exception {
        TestSM4Cipher expectedCipher = new TestSM4Cipher();
        expectedCipher.initCtr();
        byte[] expected = expectedCipher.doFinalWithValidInput();

        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        CloseFailingCipher oldCipher = new CloseFailingCipher();
        cipher.replaceCipher(oldCipher);

        byte[] actual = cipher.doFinalWithValidInput();

        assertArrayEquals(expected, actual);
        assertTrue(oldCipher.closed);
        assertArrayEquals(expected, cipher.doFinalWithValidInput());
    }

    @Test
    public void testStreamResetCloseFailureIsSuppressedOnDoFinalFailure() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        cipher.replaceCipher(new ErrorAndCloseFailingCipher());

        try {
            cipher.doFinalWithValidInput();
            fail("Expected doFinal error");
        } catch (AssertionError expected) {
            assertEquals("primary failure", expected.getMessage());
            assertEquals(1, expected.getSuppressed().length);
            assertTrue(expected.getSuppressed()[0].getMessage().contains("close failure"));
        }
    }

    @Test
    public void testStreamResetConstructionFailureClosesPreviousCipherAndFailsClosed() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        CloseTrackingCipher oldCipher = new CloseTrackingCipher();
        cipher.replaceCipher(oldCipher);
        cipher.replaceResetKey(new byte[15]);

        try {
            cipher.doFinalWithValidInput();
            fail("Expected reset failure");
        } catch (RuntimeException expected) {
            assertTrue(expected.getMessage().contains("Key must be 16 bytes"));
        }

        assertTrue(oldCipher.closed);
        assertFalse(cipher.isInitialized());
        try {
            cipher.doFinalWithValidInput();
            fail("Expected cipher to be failed closed");
        } catch (IllegalStateException expected) {
            assertEquals("Cipher not initialized", expected.getMessage());
        }
    }

    @Test
    public void testStreamResetClosesPreviousCipher() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        CloseTrackingCipher oldCipher = new CloseTrackingCipher();
        cipher.replaceCipher(oldCipher);

        cipher.doFinalWithValidInput();

        assertTrue(oldCipher.closed);
    }

    @Test
    public void testReinitClosesPreviousCipher() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.initCtr();
        CloseTrackingCipher oldCipher = new CloseTrackingCipher();
        cipher.replaceCipher(oldCipher);

        cipher.initCtr();

        assertTrue(oldCipher.closed);
    }

    @Test
    public void testInvalidIvIsReportedAsInvalidAlgorithmParameter() throws Exception {
        TestSM4Cipher cipher = new TestSM4Cipher();
        cipher.engineSetMode("CTR");
        cipher.engineSetPadding("NOPADDING");

        try {
            cipher.engineInit(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(SM4_KEY, "SM4"),
                    new IvParameterSpec(new byte[15]),
                    new SecureRandom());
            fail("Expected invalid IV parameter");
        } catch (InvalidAlgorithmParameterException expected) {
            assertEquals("IV must be 16 bytes", expected.getMessage());
        }
    }

    @Test
    public void testDoFinalRejectsInvalidInputRangeBeforeCipherUpdate() throws Exception {
        TestSM4Cipher encryptCipher = new TestSM4Cipher();
        encryptCipher.initCtr();
        encryptCipher.replaceCipher(new ErrorOnUpdateCipher());
        expectInvalidInputRange(() -> encryptCipher.doFinalWithInvalidInputRange());

        TestSM4Cipher decryptCipher = new TestSM4Cipher();
        decryptCipher.initCtrDecrypt();
        decryptCipher.replaceCipher(new ErrorOnUpdateCipher());
        expectInvalidInputRange(() -> decryptCipher.doFinalWithInvalidInputRange());
    }

    private static final class TestSM4Cipher extends SM4Cipher {
        void initCtr() throws Exception {
            engineSetMode("CTR");
            engineSetPadding("NOPADDING");
            engineInit(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(SM4_KEY, "SM4"),
                    new IvParameterSpec(IV),
                    new SecureRandom());
        }

        void initCtrDecrypt() throws Exception {
            engineSetMode("CTR");
            engineSetPadding("NOPADDING");
            engineInit(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(SM4_KEY, "SM4"),
                    new IvParameterSpec(IV),
                    new SecureRandom());
        }

        void replaceResetKey(byte[] key) {
            this.key = key;
        }

        void replaceCipher(SymmetricCipherImpl symmetricCipher) {
            this.symmetricCipher = symmetricCipher;
        }

        boolean isInitialized() {
            return initialized;
        }

        byte[] doFinalWithInvalidInputRange() throws Exception {
            return engineDoFinal(new byte[16], 10, 16);
        }

        byte[] doFinalWithValidInput() throws Exception {
            return engineDoFinal(new byte[16], 0, 16);
        }
    }

    private interface ThrowingOperation {
        void run() throws Exception;
    }

    private static void expectInvalidInputRange(ThrowingOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected invalid input range");
        } catch (IllegalArgumentException expected) {
            assertEquals("Invalid input offset or length", expected.getMessage());
        }
    }

    private static final class RuntimeExceptionOnUpdateCipher extends SymmetricCipherImpl {
        RuntimeExceptionOnUpdateCipher() {
            super("SM4", "CTR", SM4_KEY, IV, SymmetricCipherImpl.MODE_ENCRYPT, SymmetricCipherImpl.PADDING_NONE);
        }

        @Override
        public byte[] update(byte[] input, int inputOffset, int inputLen) {
            throw new RuntimeException("primary failure");
        }
    }

    private static final class ErrorOnUpdateCipher extends SymmetricCipherImpl {
        ErrorOnUpdateCipher() {
            super("SM4", "CTR", SM4_KEY, IV, SymmetricCipherImpl.MODE_ENCRYPT, SymmetricCipherImpl.PADDING_NONE);
        }

        @Override
        public byte[] update(byte[] input, int inputOffset, int inputLen) {
            throw new AssertionError("primary failure");
        }
    }

    private static class CloseFailingCipher extends SymmetricCipherImpl {
        private boolean closed;
        private boolean failOnClose = true;

        CloseFailingCipher() {
            super("SM4", "CTR", SM4_KEY, IV, SymmetricCipherImpl.MODE_ENCRYPT, SymmetricCipherImpl.PADDING_NONE);
        }

        @Override
        public synchronized void close() {
            closed = true;
            super.close();
            if (failOnClose) {
                failOnClose = false;
                throw new RuntimeException("close failure");
            }
        }
    }

    private static final class ErrorAndCloseFailingCipher extends CloseFailingCipher {
        @Override
        public byte[] update(byte[] input, int inputOffset, int inputLen) {
            throw new AssertionError("primary failure");
        }
    }

    private static final class CloseTrackingCipher extends SymmetricCipherImpl {
        private boolean closed;

        CloseTrackingCipher() {
            super("SM4", "CTR", SM4_KEY, IV, SymmetricCipherImpl.MODE_ENCRYPT, SymmetricCipherImpl.PADDING_NONE);
        }

        @Override
        public synchronized void close() {
            closed = true;
            super.close();
        }
    }
}
