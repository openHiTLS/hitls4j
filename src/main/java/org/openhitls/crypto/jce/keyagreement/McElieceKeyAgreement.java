package org.openhitls.crypto.jce.keyagreement;

import org.openhitls.crypto.core.pqc.McElieceImpl;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.jce.key.McElieceCiphertextKey;
import org.openhitls.crypto.jce.key.McEliecePrivateKeyImpl;
import org.openhitls.crypto.jce.key.McEliecePublicKeyImpl;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class McElieceKeyAgreement extends KeyAgreementSpi {
    private McElieceImpl mcElieceImpl;
    private McEliecePrivateKeyImpl mcEliecePrivateKey;
    private McEliecePublicKeyImpl mcEliecePublicKey;
    private String parameterSet;
    private byte[] ciphertext;
    private byte[] sharedKey;

    private static final String PARAM_REGEX =
            "^McEliece-(6688128|6688128f|6688128pc|6688128pcf|6960119|6960119f|6960119pc|6960119pcf|8192128|8192128f|8192128pc|8192128pcf)$";

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        init(key, null, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof McElieceParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Parameters must be an instance of McElieceParameterSpec");
        }
        init(key, (McElieceParameterSpec) params, random);
    }

    private void init(Key key, McElieceParameterSpec params, SecureRandom random) throws InvalidKeyException {
        clearState();

        McEliecePrivateKeyImpl newPrivateKey = null;
        McEliecePublicKeyImpl newPublicKey = null;
        if (key instanceof McEliecePrivateKeyImpl) {
            newPrivateKey = (McEliecePrivateKeyImpl) key;
        } else if (key instanceof McEliecePublicKeyImpl) {
            newPublicKey = (McEliecePublicKeyImpl) key;
        } else {
            throw new InvalidKeyException("Key must be an instance of McEliecePrivateKeyImpl or McEliecePublicKeyImpl");
        }

        String newParameterSet;
        if (params != null) {
            newParameterSet = params.getName();
            if (!newParameterSet.matches(PARAM_REGEX)) {
                throw new InvalidKeyException("Unsupported Classic McEliece parameter set: " + newParameterSet);
            }
        } else if (newPrivateKey != null) {
            McElieceParameterSpec keyParams = newPrivateKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("Classic McEliece key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else if (newPublicKey != null) {
            McElieceParameterSpec keyParams = newPublicKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("Classic McEliece key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else {
            throw new InvalidKeyException("Classic McEliece parameter set not specified");
        }

        byte[] privateKeyEncoded = null;
        McElieceImpl newImpl;
        if (newPrivateKey != null) {
            try {
                privateKeyEncoded = newPrivateKey.getEncoded();
                newImpl = new McElieceImpl(newParameterSet, null, privateKeyEncoded);
            } finally {
                SensitiveDataUtil.clear(privateKeyEncoded);
            }
        } else {
            newImpl = new McElieceImpl(newParameterSet, newPublicKey.getEncoded(), null);
        }

        mcEliecePrivateKey = newPrivateKey;
        mcEliecePublicKey = newPublicKey;
        parameterSet = newParameterSet;
        mcElieceImpl = newImpl;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("Only one phase is supported for Classic McEliece");
        }

        if (key != null) {
            // This is the decapsulation case
            if (key instanceof McElieceCiphertextKey) {
                this.ciphertext = ((McElieceCiphertextKey) key).getEncoded();
                clearPendingSharedKey();
            } else {
                throw new InvalidKeyException("Expected McElieceCiphertextKey for decapsulation");
            }
            return null;
        } else {
            // This is the encapsulation case - generate ciphertext and shared secret
            if (mcEliecePublicKey == null) {
                throw new IllegalStateException("Classic McEliece not initialized with public key");
            }
            byte[][] result = mcElieceImpl.encapsulate();
            this.ciphertext = result[0];
            this.sharedKey = result[1];
            return new McElieceCiphertextKey(ciphertext);
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        // return encapsulate generated sharedKey
        if (sharedKey != null) {
            byte[] result = sharedKey;
            sharedKey = null;  // Clear after use
            return result;
        }
        // return decapsulate generated sharedKey
        if (mcEliecePrivateKey == null) {
            throw new IllegalStateException("Classic McEliece private key not initialized");
        }
        if (ciphertext == null) {
            throw new IllegalStateException("Ciphertext cannot be null");
        }

        return mcElieceImpl.decapsulate(ciphertext);
    }

    private void clearPendingState() {
        clearPendingSharedKey();
        ciphertext = null;
    }

    private void clearState() {
        clearPendingState();
        McElieceImpl oldImpl = mcElieceImpl;
        mcElieceImpl = null;
        mcEliecePrivateKey = null;
        mcEliecePublicKey = null;
        parameterSet = null;
        if (oldImpl != null) {
            oldImpl.close();
        }
    }

    private void clearPendingSharedKey() {
        if (sharedKey != null) {
            Arrays.fill(sharedKey, (byte) 0);
            sharedKey = null;
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, javax.crypto.ShortBufferException {
        byte[] secret = engineGenerateSecret();
        if (offset < 0 || sharedSecret.length - offset < secret.length) {
            throw new javax.crypto.ShortBufferException("Invalid offset or insufficient space in sharedSecret array");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String s) throws InvalidParameterException {
        throw new InvalidParameterException("Classic McEliece not support");
    }
}
