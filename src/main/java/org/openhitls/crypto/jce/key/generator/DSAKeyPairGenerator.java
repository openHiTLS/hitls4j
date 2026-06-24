package org.openhitls.crypto.jce.key.generator;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import org.openhitls.crypto.core.asymmetric.DSAImpl;
import org.openhitls.crypto.jce.key.DSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.DSAPublicKeyImpl;

public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private DSAParameterSpec params;
    private SecureRandom random;
    private int keysize = 1024; // Default key size

    public DSAKeyPairGenerator() {
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        this.random = random;
        // Note: actual parameter generation will be done in generateKeyPair
        // as we're using pre-defined parameters in our implementation
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof DSAParameterSpec)) {
            throw new InvalidAlgorithmParameterException("DSAParameterSpec required");
        }
        this.params = (DSAParameterSpec) params;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] privKeyBytes = null;
        try {
            try (DSAImpl dsa = new DSAImpl()) {
                // Set parameters if provided
                if (params != null) {
                    byte[] p = params.getP().toByteArray();
                    byte[] q = params.getQ().toByteArray();
                    byte[] g = params.getG().toByteArray();

                    // Remove leading zeros if present
                    if (p[0] == 0) {
                        byte[] tmp = new byte[p.length - 1];
                        System.arraycopy(p, 1, tmp, 0, tmp.length);
                        p = tmp;
                    }
                    if (q[0] == 0) {
                        byte[] tmp = new byte[q.length - 1];
                        System.arraycopy(q, 1, tmp, 0, tmp.length);
                        q = tmp;
                    }
                    if (g[0] == 0) {
                        byte[] tmp = new byte[g.length - 1];
                        System.arraycopy(g, 1, tmp, 0, tmp.length);
                        g = tmp;
                    }

                    dsa.setParameters(p, q, g);
                }

                // Generate the key pair
                dsa.generateKeyPair();

                // Get the generated keys
                byte[] pubKeyBytes = dsa.getPublicKey();
                privKeyBytes = dsa.getPrivateKey();

                // Create JCE key objects
                DSAPublicKey publicKey = new DSAPublicKeyImpl(params, pubKeyBytes);
                DSAPrivateKey privateKey = new DSAPrivateKeyImpl(params, privKeyBytes);
                return new KeyPair(publicKey, privateKey);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate DSA key pair", e);
        } finally {
            if (privKeyBytes != null) {
                Arrays.fill(privKeyBytes, (byte) 0);
            }
        }
    }
}
