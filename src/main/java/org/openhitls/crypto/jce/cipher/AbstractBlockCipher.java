package org.openhitls.crypto.jce.cipher;

import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.symmetric.SymmetricCipherImpl;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Locale;

public abstract class AbstractBlockCipher extends CipherSpi {
    protected SymmetricCipherImpl symmetricCipher;
    protected int opmode;
    protected byte[] key;
    protected byte[] iv;
    protected String mode;
    protected String padding = "NOPADDING";
    protected boolean initialized = false;
    protected boolean requiresIV;

    public abstract String getAlgorithmName();
    public abstract void validateKeySize(byte[] keyBytes) throws InvalidKeyException;
    public abstract String[] getSupportedModes();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        mode = mode.toUpperCase(Locale.ROOT);
        if (!Arrays.asList(getSupportedModes()).contains(mode)) {
            throw new NoSuchAlgorithmException("Mode " + mode + " not supported");
        }
        
        switch (mode) {
            case "ECB":
                requiresIV = false;
                break;
            case "CBC":
            case "CTR":
            case "CFB":
            case "OFB":
            case "GCM":
            case "XTS":
                requiresIV = true;
                break;
            default:
                throw new NoSuchAlgorithmException("Mode " + mode + " not supported");
        }
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        String paddingUpper = padding.toUpperCase(Locale.ROOT);
        if (!paddingUpper.equals("NOPADDING") && !paddingUpper.equals("PKCS5PADDING") && !paddingUpper.equals("PKCS7PADDING")
            && !paddingUpper.equals("ZEROSPADDING") && !paddingUpper.equals("ISO7816PADDING") && !paddingUpper.equals("X923PADDING")) {
            throw new NoSuchPaddingException("Padding " + padding + " not supported");
        }
        this.padding = paddingUpper;
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int blockSize = engineGetBlockSize();

        // For stream cipher modes (CTR, CFB, OFB) and GCM mode, output size equals input size
        if (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || mode.equals("GCM")) {
            return inputLen;
        }

        // For block cipher modes (ECB, CBC)
        if (opmode == Cipher.ENCRYPT_MODE) {
            if ("NOPADDING".equalsIgnoreCase(padding)) {
                // For NoPadding, input must be multiple of block size
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for NoPadding");
                }
                return inputLen;
            } else {
                // For padded modes, output will be rounded up to next block size
                // Example: if input is 20 bytes and block size is 16:
                // Need to pad to next multiple of 16, so 32 bytes
                return ((inputLen + blockSize) / blockSize) * blockSize;
            }
        } else { // Cipher.DECRYPT_MODE
            if ("NOPADDING".equalsIgnoreCase(padding)) {
                // For NoPadding, output size equals input size
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for NoPadding");
                }
                return inputLen;
            } else {
                // For padded modes, output will be at most input size
                // (could be less due to padding removal)
                if (inputLen % blockSize != 0) {
                    throw new IllegalArgumentException("Input length must be multiple of " + blockSize + " for decryption");
                }
                return inputLen;
            }
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return iv != null ? iv.clone() : null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key must be a SecretKeySpec");
        }

        byte[] keyBytes = key.getEncoded();
        try {
            validateKeySize(keyBytes);
            byte[] newIv = null;
            SymmetricCipherImpl oldCipher = symmetricCipher;
            SymmetricCipherImpl newCipher = null;
            try {
                int sm4Mode = (opmode == Cipher.ENCRYPT_MODE) ? SymmetricCipherImpl.MODE_ENCRYPT : SymmetricCipherImpl.MODE_DECRYPT;
                int paddingMode = getPaddingMode();

                if (params == null) {
                    newIv = null;
                } else if (params instanceof IvParameterSpec) {
                    newIv = ((IvParameterSpec)params).getIV();
                    if (newIv.length != 16) {
                        throw new InvalidAlgorithmParameterException("IV must be 16 bytes");
                    }
                } else if (params instanceof GCMParameterSpec) {
                    GCMParameterSpec gcmParams = (GCMParameterSpec) params;
                    newIv = gcmParams.getIV();
                    if (newIv.length != 16) {
                        throw new InvalidAlgorithmParameterException("IV must be 16 bytes");
                    }

                    // For GCM mode, set the tag length in bits (converted to bytes)
                    int tagLengthBits = gcmParams.getTLen();
                    if (tagLengthBits < 32 || tagLengthBits > 128 || (tagLengthBits % 8) != 0) {
                        throw new InvalidAlgorithmParameterException("Tag length must be 32-128 bits and a multiple of 8");
                    }
                } else {
                    throw new InvalidAlgorithmParameterException("Unsupported parameter type: " + params.getClass().getName());
                }

                // Check if we need an IV but don't have one
                if (requiresIV && newIv == null) {
                    throw new InvalidAlgorithmParameterException(mode + " mode requires an IV");
                }

                // Check if we have an IV but don't need one
                if (!requiresIV && newIv != null) {
                    throw new InvalidAlgorithmParameterException(mode + " mode cannot use IV");
                }

                // Initialize the cipher
                newCipher = new SymmetricCipherImpl(getAlgorithmName(), mode, keyBytes, newIv, sm4Mode, paddingMode);
                
                // For GCM mode, set the tag length
                if ("GCM".equals(mode) && params instanceof GCMParameterSpec) {
                    int tagLengthBits = ((GCMParameterSpec) params).getTLen();
                    int tagLengthBytes = tagLengthBits / 8;
                    newCipher.setTagLength(tagLengthBytes);
                }
            } catch (InvalidAlgorithmParameterException e) {
                NativeResourceUtil.closeSuppressing(newCipher, e);
                throw e;
            } catch (RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newCipher, e);
                throw new InvalidKeyException("Failed to initialize cipher: " + e.getMessage(), e);
            }

            try {
                symmetricCipher = NativeResourceUtil.replaceAfterClosing(oldCipher, newCipher, failure -> failure);
                newCipher = null;
            } catch (RuntimeException e) {
                NativeResourceUtil.closeSuppressing(newCipher, e);
                throw e;
            }

            byte[] oldKey = this.key;
            this.key = keyBytes;
            keyBytes = null;
            this.opmode = opmode;
            this.iv = newIv;
            initialized = true;
            SensitiveDataUtil.clear(oldKey);
        } finally {
            SensitiveDataUtil.clear(keyBytes);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            try {
                paramSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Cannot process algorithm parameters");
            }
        }
        engineInit(opmode, key, paramSpec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        validateInputRange(input, inputOffset, inputLen);

        try {
            return symmetricCipher.update(input, inputOffset, inputLen);
        } catch (Exception e) {
            throw new RuntimeException("Error during update operation: " + e.getMessage());
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        validateInputRange(input, inputOffset, inputLen);

        // For NoPadding mode, validate input length is multiple of block size
        if ("NOPADDING".equalsIgnoreCase(padding) && ("CBC".equals(mode) || "ECB".equals(mode))) {
            if (inputLen % engineGetBlockSize() != 0) {
                throw new IllegalBlockSizeException("Input length must be multiple of " + engineGetBlockSize() + " when using NoPadding");
            }
        }

        boolean resetAfterFinal = isStreamMode();
        Throwable finalFailure = null;
        try {
            byte[] result;
            if (opmode == Cipher.ENCRYPT_MODE) {
                // First update with input if any
                if (hasInput(input, inputLen)) {
                    result = symmetricCipher.update(input, inputOffset, inputLen);
                } else {
                    result = new byte[0];
                }
                if ("GCM".equals(mode)) {   
                    byte[] tag = symmetricCipher.getTag();
                    byte[] combined = new byte[result.length + tag.length];
                    System.arraycopy(result, 0, combined, 0, result.length);
                    System.arraycopy(tag, 0, combined, result.length, tag.length);
                    result = combined;
                } else if (!mode.equals("XTS")) { // For XTS mode, we don't need a final block as it operates directly on blocks
                    // Then get final block
                    byte[] finalBlock = symmetricCipher.doFinal();
                    
                    // Combine results if necessary
                    if (finalBlock != null && finalBlock.length > 0) {
                        byte[] combined = new byte[result.length + finalBlock.length];
                        System.arraycopy(result, 0, combined, 0, result.length);
                        System.arraycopy(finalBlock, 0, combined, result.length, finalBlock.length);
                        return combined;
                    }
                }
                return result;
            } else {
                // DECRYPT MODE
                if (hasInput(input, inputLen)) {
                    if ("GCM".equals(mode)) {
                        // For GCM mode, separate the tag from the ciphertext
                        int tagLength = symmetricCipher.getTagLength();
                        if (inputLen <= tagLength) {
                            throw new IllegalBlockSizeException("Input length must be greater than tag length (" + tagLength + ")");
                        }
                        int cipherTextLength = inputLen - tagLength;
                        byte[] cipherText = Arrays.copyOfRange(input, inputOffset, inputOffset + cipherTextLength);
                        byte[] tag = Arrays.copyOfRange(input, inputOffset + cipherTextLength, inputOffset + inputLen);
                        
                        // Process the ciphertext
                        result = symmetricCipher.update(cipherText, 0, cipherTextLength);
                        
                        // Verify the tag
                        byte[] computedTag = symmetricCipher.getTag();
                        if (!Arrays.equals(tag, computedTag)) {
                            throw new IllegalStateException("Invalid tag");
                        }
                        return result;
                    } else {
                        // For non-GCM modes, process normally
                        result = symmetricCipher.update(input, inputOffset, inputLen);
                    }
                } else {
                    result = new byte[0];
                }
                
                if ("XTS".equals(mode)) {
                    // For XTS mode, no final block needed
                    return result;
                } else {
                    // For other modes, get final block if needed
                    byte[] finalBlock = symmetricCipher.doFinal();
                    if (finalBlock != null && finalBlock.length > 0) {
                        byte[] combined = new byte[result.length + finalBlock.length];
                        System.arraycopy(result, 0, combined, 0, result.length);
                        System.arraycopy(finalBlock, 0, combined, result.length, finalBlock.length);
                        return combined;
                    }
                    return result;
                }
            }
        } catch (Exception e) {
            IllegalStateException wrappedFailure = new IllegalStateException("Error during final operation", e);
            finalFailure = wrappedFailure;
            throw wrappedFailure;
        } catch (Error e) {
            finalFailure = e;
            throw e;
        } finally {
            if (resetAfterFinal) {
                resetStreamCipherAfterFinal(finalFailure);
            }
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

    @Override
    protected void engineUpdateAAD(byte[] aad, int offset, int len) throws UnsupportedOperationException {
        if (mode.equals("GCM")) {
            symmetricCipher.updateAAD(aad, offset, len);
        } else {
            throw new UnsupportedOperationException("Update AAD is only supported in GCM mode");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv != null) {
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance(getAlgorithmName());
                params.init(new IvParameterSpec(iv));
                return params;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    protected int getPaddingMode() {
        // Stream cipher modes (CTR, CFB, OFB, GCM) and XTS mode don't use padding
        if (!padding.equalsIgnoreCase("NOPADDING") && 
            (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || 
             mode.equals("GCM") || mode.equals("XTS"))) {
            throw new IllegalArgumentException("Stream cipher modes and authenticated encryption must use NOPADDING");
        }
        switch (padding.toUpperCase(Locale.ROOT)) {
            case "NOPADDING":
                return SymmetricCipherImpl.PADDING_NONE;
            case "ZEROSPADDING":
                return SymmetricCipherImpl.PADDING_ZEROS;
            case "ISO7816PADDING":
                return SymmetricCipherImpl.PADDING_ISO7816;
            case "X923PADDING":
                return SymmetricCipherImpl.PADDING_X923;
            case "PKCS5PADDING":
                return SymmetricCipherImpl.PADDING_PKCS5;
            case "PKCS7PADDING":
                return SymmetricCipherImpl.PADDING_PKCS7;
            default:
                throw new IllegalArgumentException("Unsupported padding mode: " + padding);
        }
    }

    private boolean isStreamMode() {
        return mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB");
    }

    private static boolean hasInput(byte[] input, int inputLen) {
        return input != null && inputLen > 0;
    }

    private static void validateInputRange(byte[] input, int inputOffset, int inputLen) {
        if (inputOffset < 0 || inputLen < 0) {
            throw new IllegalArgumentException("Invalid input offset or length");
        }
        if (input == null) {
            if (inputLen == 0) {
                return;
            }
            throw new IllegalArgumentException("Input buffer cannot be null when input length is non-zero");
        }
        if (inputOffset > input.length - inputLen) {
            throw new IllegalArgumentException("Invalid input offset or length");
        }
    }

    private void resetStreamCipherAfterFinal(Throwable finalFailure) {
        RuntimeException closeFailure;
        try {
            closeFailure = resetStreamCipher();
        } catch (RuntimeException resetFailure) {
            throwOrSuppress(resetFailure, finalFailure);
            return;
        }

        if (closeFailure == null) {
            return;
        }
        if (finalFailure != null) {
            finalFailure.addSuppressed(closeFailure);
            return;
        }
        // Reset succeeded; do not replace a successful doFinal result with old-context close failure.
    }

    private RuntimeException resetStreamCipher() {
        int cipherMode = (opmode == Cipher.ENCRYPT_MODE) ? SymmetricCipherImpl.MODE_ENCRYPT : SymmetricCipherImpl.MODE_DECRYPT;
        SymmetricCipherImpl oldCipher = symmetricCipher;
        SymmetricCipherImpl newCipher;
        try {
            newCipher = new SymmetricCipherImpl(getAlgorithmName(), mode, this.key, this.iv, cipherMode, SymmetricCipherImpl.PADDING_NONE);
        } catch (RuntimeException | Error resetFailure) {
            NativeResourceUtil.closeSuppressing(oldCipher, resetFailure);
            symmetricCipher = null;
            initialized = false;
            throw resetFailure;
        }
        symmetricCipher = newCipher;
        return NativeResourceUtil.closeAndCapture(oldCipher);
    }

    private static void throwOrSuppress(RuntimeException failure, Throwable primaryFailure) {
        if (primaryFailure != null) {
            primaryFailure.addSuppressed(failure);
        } else {
            throw failure;
        }
    }
} 
