package org.openhitls.crypto.core;

import java.util.Arrays;

public final class SensitiveDataUtil {
    private SensitiveDataUtil() {
    }

    public static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    public static byte[] copy(byte[] value) {
        return value != null ? value.clone() : null;
    }

    public static KeyMaterial copyKeyMaterial(byte[] publicKey, byte[] privateKey) {
        return new KeyMaterial(copy(publicKey), copy(privateKey));
    }

    public static final class KeyMaterial {
        private final byte[] publicKey;
        private final byte[] privateKey;

        private KeyMaterial(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public byte[] publicKey() {
            return publicKey;
        }

        public byte[] privateKey() {
            return privateKey;
        }

        public void clearPrivate() {
            clear(privateKey);
        }
    }
}
