package org.openhitls.crypto.jce.state;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class HbsStateRecord {
    private final String keyId;
    private final String algorithm;
    private final String parameterSet;
    private final byte[] publicKey;
    private final byte[] privateState;
    private final long remainingSignatures;
    private final long version;

    public HbsStateRecord(String keyId, String algorithm, String parameterSet, byte[] publicKey,
                          byte[] privateState, long remainingSignatures, long version) {
        if (keyId == null || algorithm == null || parameterSet == null || publicKey == null || privateState == null) {
            throw new NullPointerException("state record fields cannot be null");
        }
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.parameterSet = parameterSet;
        this.publicKey = publicKey.clone();
        this.privateState = privateState.clone();
        this.remainingSignatures = remainingSignatures;
        this.version = version;
    }

    public static HbsStateRecord create(String algorithm, String parameterSet, byte[] publicKey, byte[] privateState) {
        return new HbsStateRecord(computeKeyId(algorithm, parameterSet, publicKey), algorithm, parameterSet,
                publicKey, privateState, -1L, 0L);
    }

    public static String computeKeyId(String algorithm, String parameterSet, byte[] publicKey) {
        if (algorithm == null || parameterSet == null || publicKey == null) {
            throw new NullPointerException("algorithm, parameterSet and publicKey cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(algorithm.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(parameterSet.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(publicKey);
            return toHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        char[] table = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            hex[2 * i] = table[value >>> 4];
            hex[2 * i + 1] = table[value & 0x0f];
        }
        return new String(hex);
    }

    public HbsStateRecord withPrivateState(byte[] updatedPrivateState, long updatedRemainingSignatures) {
        return new HbsStateRecord(keyId, algorithm, parameterSet, publicKey, updatedPrivateState,
                updatedRemainingSignatures, version + 1);
    }

    public String getKeyId() {
        return keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getParameterSet() {
        return parameterSet;
    }

    public byte[] getPublicKey() {
        return publicKey.clone();
    }

    public byte[] getPrivateState() {
        return privateState.clone();
    }

    public long getRemainingSignatures() {
        return remainingSignatures;
    }

    public long getVersion() {
        return version;
    }
}
