package org.openhitls.crypto.jce.spec;

public class MLDSANamedParamSpec extends MLDSAParameterSpec{
    private final String paramSetName;

    public MLDSANamedParamSpec(String paramSetName, int k, int l, int gamma1, int gamma2, int tau,
                               int beta, int omega, int eta) {
        super(k, l, gamma1, gamma2, tau, beta, omega, eta);
        this.paramSetName = paramSetName;
    }

    public String getName() {
        return paramSetName;
    }

    public static MLDSANamedParamSpec getMLDSA44Params() {
        return new MLDSANamedParamSpec(
                "ML-DSA-44",
                4,              // k
                4,              // l
                1 << 17,        // gamma1
                (q-1)/88,       // gamma2
                39,             // tau
                78,             // beta
                80,             // omega
                2               // eta
        );
    }

    public static MLDSANamedParamSpec getMLDSA65Params() {
        return new MLDSANamedParamSpec(
                "ML-DSA-65",
                6,              // k
                5,              // l
                1 << 19,        // gamma1
                (q-1)/32,       // gamma2
                49,             // tau
                196,            // beta
                55,             // omega
                4               // eta
        );
    }

    public static MLDSANamedParamSpec getMLDSA87Params() {
        return new MLDSANamedParamSpec(
                "ML-DSA-87",
                8,              // k
                7,              // l
                1 << 19,        // gamma1
                (q-1)/32,       // gamma2
                60,             // tau
                120,            // beta
                75,             // omega
                2               // eta
        );
    }
}
