package org.openhitls.crypto.jce.key.generator;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import org.openhitls.crypto.core.asymmetric.RSAImpl;
import org.openhitls.crypto.jce.key.RSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.RSAPublicKeyImpl;
import java.math.BigInteger;

public class RSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private RSAKeyGenParameterSpec params;
    private SecureRandom random;
    private int keysize = 2048; // Default key size
    private BigInteger publicExponent = BigInteger.valueOf(65537); // Default public exponent

    public RSAKeyPairGenerator() {
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize < 512 || keysize > 16384 || keysize % 8 != 0) {
            throw new IllegalArgumentException("Invalid key size for RSA: " + keysize);
        }
        this.keysize = keysize;
        this.random = random;
        this.params = new RSAKeyGenParameterSpec(keysize, publicExponent);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof RSAKeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("RSAKeyGenParameterSpec required");
        }
        RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec) params;
        this.keysize = rsaParams.getKeysize();
        this.publicExponent = rsaParams.getPublicExponent();
        this.random = random;
        this.params = rsaParams;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            RSAImpl rsa = new RSAImpl();

            // Set parameters
            byte[] e = publicExponent.toByteArray();

            // Remove leading zero if present (BigInteger's sign bit)
            if (e.length > 1 && e[0] == 0) {
                byte[] tmp = new byte[e.length - 1];
                System.arraycopy(e, 1, tmp, 0, tmp.length);
                e = tmp;
            }

            rsa.setParameters(e, keysize);

            // Generate the key pair
            byte[][] keyPair = rsa.generateKeyPair();
            byte[] pubKeyBytes = keyPair[0];  // modulus
            byte[] privKeyBytes = keyPair[1]; // private exponent

            // Create JCE key objects
            RSAPublicKey publicKey = new RSAPublicKeyImpl(pubKeyBytes, publicExponent);
            RSAPrivateKey privateKey = new RSAPrivateKeyImpl(privKeyBytes, pubKeyBytes);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to generate RSA key pair", ex);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
} 