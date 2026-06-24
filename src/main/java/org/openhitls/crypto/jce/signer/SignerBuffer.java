package org.openhitls.crypto.jce.signer;

import java.security.SignatureException;
import java.util.Arrays;

final class SignerBuffer {
    private SignerBuffer() {
    }

    static byte[] append(byte[] current, byte[] input, int offset, int length) throws SignatureException {
        validateUpdateInput(input, offset, length);
        if (current == null) {
            byte[] appended = new byte[length];
            System.arraycopy(input, offset, appended, 0, length);
            return appended;
        }

        validateAdditionalLength(current.length, length);
        try {
            byte[] appended = new byte[current.length + length];
            System.arraycopy(current, 0, appended, 0, current.length);
            System.arraycopy(input, offset, appended, current.length, length);
            clear(current);
            return appended;
        } catch (OutOfMemoryError e) {
            clear(current);
            throw e;
        }
    }

    static void validateUpdateInput(byte[] input, int offset, int length) throws SignatureException {
        if (input == null) {
            throw new SignatureException("Input buffer must not be null");
        }
        if (offset < 0 || length < 0 || offset > input.length - length) {
            throw new SignatureException("Invalid input buffer parameters");
        }
    }

    static void validateAdditionalLength(int currentLength, int additionalLength) throws SignatureException {
        if (additionalLength > Integer.MAX_VALUE - currentLength) {
            throw new SignatureException("Input is too large");
        }
    }

    static byte[] clear(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
        return null;
    }

    static byte[] copyOf(byte[] buffer, int length) {
        try {
            return Arrays.copyOf(buffer, length);
        } catch (OutOfMemoryError e) {
            clear(buffer);
            throw e;
        }
    }

    static byte[] resize(byte[] buffer, int newLength) {
        try {
            byte[] resized = Arrays.copyOf(buffer, newLength);
            clear(buffer);
            return resized;
        } catch (OutOfMemoryError e) {
            clear(buffer);
            throw e;
        }
    }
}
