package org.openhitls.crypto.jce.cipher;

import javax.crypto.CipherSpi;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.util.ECCurveRegistry;
import org.openhitls.crypto.jce.util.ECKeyEncoding;

public class SM2Cipher extends CipherSpi {
    private ECDSAImpl ecdsaImpl;
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
        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                if (!(key instanceof ECPublicKey)) {
                    throw new InvalidKeyException("Public key required for encryption");
                }
                ECParameterSpec params = ((ECPublicKey)key).getParams();
                String curveName = getSM2CurveName(params);
                ECDSAImpl newImpl = null;
                try {
                    newImpl = new ECDSAImpl(
                            curveName,
                            ECKeyEncoding.encodePublicPoint(((ECPublicKey) key).getW(), params),
                            null);
                    replaceImpl(newImpl);
                    newImpl = null;
                } catch (InvalidKeyException | RuntimeException e) {
                    NativeResourceUtil.closeSuppressing(newImpl, e);
                    throw e;
                }
            } else if (opmode == Cipher.DECRYPT_MODE) {
                if (!(key instanceof ECPrivateKey)) {
                    throw new InvalidKeyException("Private key required for decryption");
                }
                ECParameterSpec params = ((ECPrivateKey)key).getParams();
                String curveName = getSM2CurveName(params);
                byte[] encodedPrivate = ECKeyEncoding.encodePrivateValue(((ECPrivateKey) key).getS(), params);
                ECDSAImpl newImpl = null;
                try {
                    newImpl = new ECDSAImpl(
                            curveName,
                            null,
                            encodedPrivate);
                    replaceImpl(newImpl);
                    newImpl = null;
                } catch (InvalidKeyException | RuntimeException e) {
                    NativeResourceUtil.closeSuppressing(newImpl, e);
                    throw e;
                } finally {
                    Arrays.fill(encodedPrivate, (byte) 0);
                }
            } else {
                throw new InvalidKeyException("Unsupported operation mode");
            }
            this.opmode = opmode;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to initialize SM2", e);
        }
    }

    private static String getSM2CurveName(ECParameterSpec params) throws InvalidKeyException {
        try {
            String curveName = ECKeyEncoding.getCurveName(params);
            if (!ECCurveRegistry.isSM2Curve(curveName)) {
                throw new InvalidKeyException("SM2 requires SM2 curve: " + curveName);
            }
            return curveName;
        } catch (InvalidKeySpecException | RuntimeException e) {
            throw new InvalidKeyException("Unsupported SM2 curve parameters", e);
        }
    }

    private void replaceImpl(ECDSAImpl newImpl) throws InvalidKeyException {
        ecdsaImpl = NativeResourceUtil.replaceAfterClosing(ecdsaImpl, newImpl,
                failure -> new InvalidKeyException("Failed to close previous SM2 context", failure));
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Ignore params as SM2 doesn't use them
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException {
        engineInit(opmode, key, random);
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
                return ecdsaImpl.encryptData(data);
            } else {
                return ecdsaImpl.decryptData(data);
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
