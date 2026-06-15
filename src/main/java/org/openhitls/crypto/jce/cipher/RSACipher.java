package org.openhitls.crypto.jce.cipher;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.openhitls.crypto.core.asymmetric.RSAImpl;

public class RSACipher extends CipherSpi {
    private RSAImpl rsaImpl;
    private int opmode;
    private Key key;
    private String padding = "PKCS1Padding";

    public RSACipher() {
        this.rsaImpl = new RSAImpl();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("Only ECB mode is supported for RSA");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"PKCS1Padding".equalsIgnoreCase(padding) && !"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("Only PKCS1Padding and NoPadding are supported for RSA");
        }
        this.padding = padding;
    }

    @Override
    protected int engineGetBlockSize() {
        if (key instanceof RSAKey) {
            int keySize = ((RSAKey) key).getModulus().bitLength() / 8;
            return "PKCS1Padding".equalsIgnoreCase(padding) ? keySize - 11 : keySize;
        }
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength() / 8;
        }
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null; // RSA doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null; // RSA doesn't use parameters
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof RSAKey)) {
            throw new InvalidKeyException("Key must be an instance of RSAKey");
        }

        if (opmode == Cipher.ENCRYPT_MODE && !(key instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Public key required for encryption");
        }
        if (opmode == Cipher.DECRYPT_MODE && !(key instanceof RSAPrivateKey)) {
            throw new InvalidKeyException("Private key required for decryption");
        }

        this.opmode = opmode;
        this.key = key;

        try {
            // Set parameters first
            RSAKey rsaKey = (RSAKey) key;
            byte[] e;
            if (key instanceof RSAPublicKey) {
                e = ((RSAPublicKey) key).getPublicExponent().toByteArray();
            } else {
                // For private key, use default public exponent (65537)
                e = new byte[] {0x01, 0x00, 0x01};
            }
            // Remove leading zero if present
            if (e.length > 0 && e[0] == 0) {
                byte[] tmp = new byte[e.length - 1];
                System.arraycopy(e, 1, tmp, 0, tmp.length);
                e = tmp;
            }
            rsaImpl.setParameters(e, rsaKey.getModulus().bitLength());

            // Then set the keys
            if (opmode == Cipher.ENCRYPT_MODE) {
                RSAPublicKey pubKey = (RSAPublicKey) key;
                byte[] modulus = pubKey.getModulus().toByteArray();
                // Remove leading zero if present
                if (modulus[0] == 0) {
                    byte[] tmp = new byte[modulus.length - 1];
                    System.arraycopy(modulus, 1, tmp, 0, tmp.length);
                    modulus = tmp;
                }
                rsaImpl.setKeys(modulus, null);
            } else {
                RSAPrivateKey privKey = (RSAPrivateKey) key;
                byte[] modulus = privKey.getModulus().toByteArray();
                byte[] privateExponent = privKey.getPrivateExponent().toByteArray();
                // Remove leading zeros if present
                if (modulus[0] == 0) {
                    byte[] tmp = new byte[modulus.length - 1];
                    System.arraycopy(modulus, 1, tmp, 0, tmp.length);
                    modulus = tmp;
                }
                if (privateExponent[0] == 0) {
                    byte[] tmp = new byte[privateExponent.length - 1];
                    System.arraycopy(privateExponent, 1, tmp, 0, tmp.length);
                    privateExponent = tmp;
                }
                rsaImpl.setKeys(modulus, privateExponent);
            }

            // Set padding mode
            rsaImpl.setPadding("NoPadding".equalsIgnoreCase(padding) ? 0 : 1);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize RSA cipher", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("RSA does not use parameters");
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("RSA does not use parameters");
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new IllegalStateException("RSA cipher cannot be updated, use doFinal() instead");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        throw new IllegalStateException("RSA cipher cannot be updated, use doFinal() instead");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] data = new byte[inputLen];
            System.arraycopy(input, inputOffset, data, 0, inputLen);

            // Check block size for encryption
            if (opmode == Cipher.ENCRYPT_MODE) {
                int maxInputSize = engineGetBlockSize();
                if (data.length > maxInputSize) {
                    throw new IllegalBlockSizeException("Data must not be longer than " + maxInputSize + " bytes");
                }
            }

            if (opmode == Cipher.ENCRYPT_MODE) {
                return rsaImpl.encrypt(data);
            } else {
                return rsaImpl.decrypt(data);
            }
        } catch (IllegalStateException e) {
            if (e.getMessage() != null && e.getMessage().contains("Error code: 16973831")) {
                throw new IllegalBlockSizeException("Data too long for RSA cipher");
            }
            throw e;
        } catch (Exception e) {
            if (e instanceof IllegalBlockSizeException) {
                throw (IllegalBlockSizeException) e;
            }
            if (e instanceof BadPaddingException) {
                throw (BadPaddingException) e;
            }
            throw new IllegalStateException("RSA operation failed", e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
} 