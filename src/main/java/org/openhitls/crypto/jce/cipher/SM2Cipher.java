package org.openhitls.crypto.jce.cipher;

import javax.crypto.CipherSpi;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import org.openhitls.crypto.core.asymmetric.SM2;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.key.SM2PrivateKey;

public class SM2Cipher extends CipherSpi {
    private SM2 sm2;
    private int opmode;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("SM2 only supports ECB mode");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NOPADDING".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0; // SM2 is not a block cipher
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen; // This is an approximation
    }

    @Override
    protected byte[] engineGetIV() {
        return null; // SM2 doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null; // SM2 doesn't use parameters
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException {
        this.opmode = opmode;
        
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (!(key instanceof SM2PublicKey)) {
                throw new InvalidKeyException("Public key required for encryption");
            }
            sm2 = new SM2(((SM2PublicKey)key).getEncoded(), null);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            if (!(key instanceof SM2PrivateKey)) {
                throw new InvalidKeyException("Private key required for decryption");
            }
            sm2 = new SM2(null, ((SM2PrivateKey)key).getEncoded());
        } else {
            throw new InvalidKeyException("Unsupported operation mode");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException {
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new UnsupportedOperationException("SM2 does not support partial updates");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new UnsupportedOperationException("SM2 does not support partial updates");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] data = new byte[inputLen];
        System.arraycopy(input, inputOffset, data, 0, inputLen);

        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                return sm2.encryptData(data);
            } else {
                return sm2.decryptData(data);
            }
        } catch (Exception e) {
            throw new BadPaddingException("Operation failed: " + e.getMessage());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
}
