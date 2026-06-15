package org.openhitls.crypto.jce.signer;

import java.security.spec.AlgorithmParameterSpec;

public class RSAPadding {
    public static final int PADDING_PKCS1 = 1;
    public static final int PADDING_PSS = 2;

    public static class PSSParameterSpec implements AlgorithmParameterSpec {
        private final String hashAlgorithm;
        private final String mgf1HashAlgorithm;
        private final int saltLength;
        private final int trailerField;

        public PSSParameterSpec(String hashAlgorithm, String mgf1HashAlgorithm, int saltLength, int trailerField) {
            this.hashAlgorithm = hashAlgorithm;
            this.mgf1HashAlgorithm = mgf1HashAlgorithm;
            this.saltLength = saltLength;
            this.trailerField = trailerField;
        }

        public PSSParameterSpec(String hashAlgorithm) {
            this(hashAlgorithm, hashAlgorithm, -1, 1); // -1 means use digest length as salt length
        }

        public String getHashAlgorithm() {
            return hashAlgorithm;
        }

        public String getMGF1HashAlgorithm() {
            return mgf1HashAlgorithm;
        }

        public int getSaltLength() {
            return saltLength;
        }

        public int getTrailerField() {
            return trailerField;
        }
    }
} 