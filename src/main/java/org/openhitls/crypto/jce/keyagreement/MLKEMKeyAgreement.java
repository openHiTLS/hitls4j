package org.openhitls.crypto.jce.keyagreement;

import org.openhitls.crypto.core.pqc.MLKEMImpl;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.jce.key.MLKEMCiphertextKey;
import org.openhitls.crypto.jce.key.MLKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class MLKEMKeyAgreement extends KeyAgreementSpi {
    private MLKEMImpl mlkemImpl;
    private MLKEMPrivateKeyImpl mlkemPrivateKey;
    private MLKEMPublicKeyImpl mlkemPublicKey;
    private String parameterSet;
    private byte[] ciphertext;
    private byte[] sharedKey;


    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        init(key, null, random);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof MLKEMParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Parameters must be an instance of MLKEMParameterSpec");
        }
        init(key, (MLKEMParameterSpec) params, random);
    }

    private void init(Key key, MLKEMParameterSpec params, SecureRandom random) throws InvalidKeyException {
        clearState();

        MLKEMPrivateKeyImpl newPrivateKey = null;
        MLKEMPublicKeyImpl newPublicKey = null;
        if (key instanceof MLKEMPrivateKeyImpl) {
            newPrivateKey = (MLKEMPrivateKeyImpl) key;
        } else if (key instanceof MLKEMPublicKeyImpl) {
            newPublicKey = (MLKEMPublicKeyImpl) key;
        } else {
            throw new InvalidKeyException("Key must be an instance of MLKEMPrivateKeyImpl or MLKEMPublicKeyImpl");
        }

        String newParameterSet;
        if (params != null) {
            newParameterSet = params.getName();
            if (!newParameterSet.matches("^ML-KEM-(512|768|1024)$")) {
                throw new InvalidKeyException("Unsupported ML-KEM parameter set: " + newParameterSet);
            }
        } else if (newPrivateKey != null) {
            MLKEMParameterSpec keyParams = newPrivateKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("ML-KEM key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else if (newPublicKey != null) {
            MLKEMParameterSpec keyParams = newPublicKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("ML-KEM key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else {
            throw new InvalidKeyException("ML-KEM parameter set not specified");
        }

        byte[] privateKeyEncoded = null;
        MLKEMImpl newImpl;
        if (newPrivateKey != null) {
            try {
                privateKeyEncoded = newPrivateKey.getEncoded();
                newImpl = new MLKEMImpl(newParameterSet, null, privateKeyEncoded);
            } finally {
                SensitiveDataUtil.clear(privateKeyEncoded);
            }
        } else {
            newImpl = new MLKEMImpl(newParameterSet, newPublicKey.getEncoded(), null);
        }

        mlkemPrivateKey = newPrivateKey;
        mlkemPublicKey = newPublicKey;
        parameterSet = newParameterSet;
        mlkemImpl = newImpl;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("Only one phase is supported for ML-KEM");
        }

        if (key != null) {
            // This is the decapsulation case
            if (key instanceof MLKEMCiphertextKey) {
                this.ciphertext = ((MLKEMCiphertextKey) key).getEncoded();
                clearPendingSharedKey();
            } else {
                throw new InvalidKeyException("Expected MLKEMCiphertextKey for decapsulation");
            }
            return null;
        } else {
            // This is the encapsulation case - generate ciphertext and shared secret
            if (mlkemPublicKey == null) {
                throw new IllegalStateException("ML-KEM not initialized with public key");
            }
            byte[][] result = mlkemImpl.encapsulate();
            this.ciphertext = result[0];
            this.sharedKey = result[1];
            return new MLKEMCiphertextKey(ciphertext);
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
        if (mlkemPrivateKey == null) {
            throw new IllegalStateException("ML-KEM private key not initialized");
        }
        if (ciphertext == null) {
            throw new IllegalStateException("Ciphertext cannot be null");
        }

        return mlkemImpl.decapsulate(ciphertext);
    }

    private void clearPendingState() {
        clearPendingSharedKey();
        ciphertext = null;
    }

    private void clearState() {
        clearPendingState();
        MLKEMImpl oldImpl = mlkemImpl;
        mlkemImpl = null;
        mlkemPrivateKey = null;
        mlkemPublicKey = null;
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
        throw new InvalidParameterException("ML-KEM not support");
    }

}
