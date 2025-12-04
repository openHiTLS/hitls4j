package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.MLDSAGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLDSANamedParamSpec;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

public class MLDSAParameters extends AlgorithmParametersSpi {
    private MLDSAParameterSpec mldsaParameterSpec;
    private String name;
    private static final Map<String, MLDSAParameterSpec> namedParams = new HashMap<>();
    static {
        namedParams.put("ML-DSA-44", MLDSANamedParamSpec.getMLDSA44Params());
        namedParams.put("ML-DSA-65", MLDSANamedParamSpec.getMLDSA65Params());
        namedParams.put("ML-DSA-87", MLDSANamedParamSpec.getMLDSA87Params());
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof MLDSAParameterSpec) {
            mldsaParameterSpec = (MLDSAParameterSpec)paramSpec;
            if (paramSpec instanceof MLDSANamedParamSpec) {
                name = ((MLDSANamedParamSpec)paramSpec).getName();
            }
        } else if (paramSpec instanceof MLDSAGenParameterSpec) {
            name = ((MLDSAGenParameterSpec)paramSpec).getName();
            MLDSAParameterSpec spec = namedParams.get(name);
            if (spec != null) {
                mldsaParameterSpec = spec;
            } else {
                throw new InvalidParameterSpecException("Unknown parameter set: " + name);
            }
        } else {
            throw new InvalidParameterSpecException("Spec is not MLDSAParameterSpec or MLDSAGenParameterSpec");
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException("paramSpec == null");
        }

        if (MLDSAParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (mldsaParameterSpec == null) {
                throw new InvalidParameterSpecException("MLDSAParameterSpec not initialized");
            }
            return (T)mldsaParameterSpec;
        }

        if (MLDSAGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T)new MLDSAGenParameterSpec(name);
            }
        }

        throw new InvalidParameterSpecException("Unknown parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected String engineToString() {
        return "ML-DSA parameter";
    }
}
