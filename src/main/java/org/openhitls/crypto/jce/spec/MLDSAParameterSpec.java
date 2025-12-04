package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class MLDSAParameterSpec implements AlgorithmParameterSpec {
    // Core ML-DSA parameters
    protected static final int n = 256; // Polynomial degree, NIST fixed value
    protected static final int q = 8380417; // Modulus, NIST fixed value
    private final int k;         // Number of polynomials in the public key
    private final int l;         // Number of polynomials in the signature
    private final int gamma1;    // Range of y coefficients
    private final int gamma2;    // Range of z coefficients
    private final int tau;       // Number of 1s in c
    private final int beta;      // Maximum coefficient of s1
    private final int omega;     // Maximum number of 1s in c
    private final int eta;       // Range of secret key coefficients

    /**
     * Creates ML-DSA domain parameters based on the specified values.
     *
     * @param k number of polynomials in the public key
     * @param l number of polynomials in the signature
     * @param gamma1 range of y coefficients
     * @param gamma2 range of z coefficients
     * @param tau number of 1s in c
     * @param beta maximum coefficient of s1
     * @param omega maximum number of 1s in c
     * @param eta range of secret key coefficients
     */
    public MLDSAParameterSpec(int k, int l, int gamma1, int gamma2, int tau,
                              int beta, int omega, int eta) {
        // Basic positive checks
        if (k <= 0 || l <= 0 || gamma1 <= 0 || gamma2 <= 0 || 
            tau <= 0 || beta <= 0 || omega <= 0 || eta <= 0) {
            throw new IllegalArgumentException("All parameters must be positive");
        }

        // Check if it matches standard parameter sets
        if (!isStandardParameterSet(k, l, gamma1, gamma2, tau, beta, omega, eta)) {
            throw new IllegalArgumentException("Parameters do not match any standard ML-DSA parameter set");
        }

        this.k = k;
        this.l = l;
        this.gamma1 = gamma1;
        this.gamma2 = gamma2;
        this.tau = tau;
        this.beta = beta;
        this.omega = omega;
        this.eta = eta;
    }

    private boolean isStandardParameterSet(int k, int l, int gamma1, int gamma2, 
                                     int tau, int beta, int omega, int eta) {
        // ML-DSA-44 parameters
        if (k == 4 && l == 4 && gamma1 == (1 << 17) && 
            gamma2 == (q-1)/88 && tau == 39 && beta == 78 && 
            omega == 80 && eta == 2) {
            return true;
        }
        
        // ML-DSA-65 parameters
        if (k == 6 && l == 5 && gamma1 == (1 << 19) && 
            gamma2 == (q-1)/32 && tau == 49 && beta == 196 && 
            omega == 55 && eta == 4) {
            return true;
        }
        
        // ML-DSA-87 parameters
        if (k == 8 && l == 7 && gamma1 == (1 << 19) && 
            gamma2 == (q-1)/32 && tau == 60 && beta == 120 && 
            omega == 75 && eta == 2) {
            return true;
        }
        
        return false;
    }

    // Getters for all parameters
    public int getK() { return k; }
    public int getL() { return l; }
    public int getGamma1() { return gamma1; }
    public int getGamma2() { return gamma2; }
    public int getTau() { return tau; }
    public int getBeta() { return beta; }
    public int getOmega() { return omega; }
    public int getEta() { return eta; }
    public static int getN() { return n; }
    public static int getQ() { return q; }
}