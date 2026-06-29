package org.openhitls.crypto.jce.keyagreement;

import org.openhitls.crypto.core.pqc.FrodoKEMImpl;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.jce.key.FrodoKEMCiphertextKey;
import org.openhitls.crypto.jce.key.FrodoKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.FrodoKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class FrodoKEMKeyAgreement extends KeyAgreementSpi {
    private FrodoKEMImpl frodoKemImpl;
    private FrodoKEMPrivateKeyImpl frodoKemPrivateKey;
    private FrodoKEMPublicKeyImpl frodoKemPublicKey;
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
        if (params != null && !(params instanceof FrodoKEMParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Parameters must be an instance of FrodoKEMParameterSpec");
        }
        init(key, (FrodoKEMParameterSpec) params, random);
    }

    private void init(Key key, FrodoKEMParameterSpec params, SecureRandom random) throws InvalidKeyException {
        clearState();

        FrodoKEMPrivateKeyImpl newPrivateKey = null;
        FrodoKEMPublicKeyImpl newPublicKey = null;
        if (key instanceof FrodoKEMPrivateKeyImpl) {
            newPrivateKey = (FrodoKEMPrivateKeyImpl) key;
        } else if (key instanceof FrodoKEMPublicKeyImpl) {
            newPublicKey = (FrodoKEMPublicKeyImpl) key;
        } else {
            throw new InvalidKeyException("Key must be an instance of FrodoKEMPrivateKeyImpl or FrodoKEMPublicKeyImpl");
        }

        String newParameterSet;
        if (params != null) {
            newParameterSet = params.getName();
            if (!newParameterSet.matches("^FrodoKEM-(640|976|1344)-(SHAKE|AES)$")) {
                throw new InvalidKeyException("Unsupported FrodoKEM parameter set: " + newParameterSet);
            }
        } else if (newPrivateKey != null) {
            FrodoKEMParameterSpec keyParams = newPrivateKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("FrodoKEM key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else if (newPublicKey != null) {
            FrodoKEMParameterSpec keyParams = newPublicKey.getParams();
            if (keyParams == null) {
                throw new InvalidKeyException("FrodoKEM key is missing parameter metadata");
            }
            newParameterSet = keyParams.getName();
        } else {
            throw new InvalidKeyException("FrodoKEM parameter set not specified");
        }

        byte[] privateKeyEncoded = null;
        FrodoKEMImpl newImpl;
        if (newPrivateKey != null) {
            try {
                privateKeyEncoded = newPrivateKey.getEncoded();
                newImpl = new FrodoKEMImpl(newParameterSet, null, privateKeyEncoded);
            } finally {
                SensitiveDataUtil.clear(privateKeyEncoded);
            }
        } else {
            newImpl = new FrodoKEMImpl(newParameterSet, newPublicKey.getEncoded(), null);
        }

        frodoKemPrivateKey = newPrivateKey;
        frodoKemPublicKey = newPublicKey;
        parameterSet = newParameterSet;
        frodoKemImpl = newImpl;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("Only one phase is supported for FrodoKEM");
        }

        if (key != null) {
            // This is the decapsulation case
            if (key instanceof FrodoKEMCiphertextKey) {
                this.ciphertext = ((FrodoKEMCiphertextKey) key).getEncoded();
                clearPendingSharedKey();
            } else {
                throw new InvalidKeyException("Expected FrodoKEMCiphertextKey for decapsulation");
            }
            return null;
        } else {
            // This is the encapsulation case - generate ciphertext and shared secret
            if (frodoKemPublicKey == null) {
                throw new IllegalStateException("FrodoKEM not initialized with public key");
            }
            byte[][] result = frodoKemImpl.encapsulate();
            this.ciphertext = result[0];
            this.sharedKey = result[1];
            return new FrodoKEMCiphertextKey(ciphertext);
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
        if (frodoKemPrivateKey == null) {
            throw new IllegalStateException("FrodoKEM private key not initialized");
        }
        if (ciphertext == null) {
            throw new IllegalStateException("Ciphertext cannot be null");
        }

        return frodoKemImpl.decapsulate(ciphertext);
    }

    private void clearPendingState() {
        clearPendingSharedKey();
        ciphertext = null;
    }

    private void clearState() {
        clearPendingState();
        FrodoKEMImpl oldImpl = frodoKemImpl;
        frodoKemImpl = null;
        frodoKemPrivateKey = null;
        frodoKemPublicKey = null;
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
        throw new InvalidParameterException("FrodoKEM not support");
    }
}
