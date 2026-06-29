package org.openhitls.crypto.jce.mac;

import org.openhitls.crypto.core.mac.HMACImpl;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import javax.crypto.MacSpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class HMAC extends MacSpi {
    private HMACImpl hmac;
    private final int macLength;
    private final String algorithm;

    protected HMAC(String algorithm, int macLength) {
        this.algorithm = algorithm;
        this.macLength = macLength;
    }

    @Override
    protected int engineGetMacLength() {
        return macLength;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key must be a SecretKeySpec");
        }

        SecretKeySpec keySpec = (SecretKeySpec) key;
        if (!algorithm.equalsIgnoreCase(keySpec.getAlgorithm())) {
            throw new InvalidKeyException("Key algorithm must be " + algorithm);
        }

        byte[] newKeyBytes = keySpec.getEncoded();
        if (newKeyBytes == null || newKeyBytes.length == 0) {
            throw new InvalidKeyException("Key bytes cannot be null or empty");
        }

        HMACImpl newHmac = null;
        try {
            newHmac = new HMACImpl(algorithm, newKeyBytes);
            hmac = NativeResourceUtil.replaceAfterClosing(hmac, newHmac,
                    failure -> new InvalidKeyException("Failed to close previous HMAC context", failure));
            newHmac = null;
        } catch (InvalidKeyException | RuntimeException e) {
            NativeResourceUtil.closeSuppressing(newHmac, e);
            throw e;
        } finally {
            SensitiveDataUtil.clear(newKeyBytes);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        byte[] data = new byte[]{input};
        hmac.update(data, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        hmac.update(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        return hmac.doFinal();
    }

    @Override
    protected void engineReset() {
        if (hmac == null) {
            throw new IllegalStateException("HMAC not initialized");
        }
        hmac.reinit();
    }

    public static final class HMACSHA224 extends HMAC {
        public HMACSHA224() {
            super("HMACSHA224", 28); // SHA-224 produces 28 bytes output
        }
    }

    public static final class HMACSHA256 extends HMAC {
        public HMACSHA256() {
            super("HMACSHA256", 32); // SHA-256 produces 32 bytes output
        }
    }

    public static final class HMACSHA384 extends HMAC {
        public HMACSHA384() {
            super("HMACSHA384", 48); // SHA-384 produces 48 bytes output
        }
    }

    public static final class HMACSHA512 extends HMAC {
        public HMACSHA512() {
            super("HMACSHA512", 64); // SHA-512 produces 64 bytes output
        }
    }

    public static final class HMACSM3 extends HMAC {
        public HMACSM3() {
            super("HMACSM3", 32); // SM3 produces 32 bytes output
        }
    }

    public static final class HMACSHA1 extends HMAC {
        public HMACSHA1() {
            super("HMACSHA1", 20); // SHA-1 produces 20 bytes output
        }
    }

    public static final class HMACSHA3_224 extends HMAC {
        public HMACSHA3_224() {
            super("HMACSHA3-224", 28); // SHA3-224 produces 28 bytes output
        }
    }

    public static final class HMACSHA3_256 extends HMAC {
        public HMACSHA3_256() {
            super("HMACSHA3-256", 32); // SHA3-256 produces 32 bytes output
        }
    }

    public static final class HMACSHA3_384 extends HMAC {
        public HMACSHA3_384() {
            super("HMACSHA3-384", 48); // SHA3-384 produces 48 bytes output
        }
    }

    public static final class HMACSHA3_512 extends HMAC {
        public HMACSHA3_512() {
            super("HMACSHA3-512", 64); // SHA3-512 produces 64 bytes output
        }
    }
}
