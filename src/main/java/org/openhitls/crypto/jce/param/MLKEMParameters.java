package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.MLKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class MLKEMParameters extends AlgorithmParametersSpi {
    private MLKEMParameterSpec mlkemParameterSpec;
    private String name;


    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("Parameter specification cannot be null");
        }

        if (paramSpec instanceof MLKEMParameterSpec) {
            mlkemParameterSpec = (MLKEMParameterSpec) paramSpec;
        } else if (paramSpec instanceof MLKEMGenParameterSpec) {
            name = ((MLKEMGenParameterSpec) paramSpec).getName();
            MLKEMParameterSpec spec = MLKEMParameterSpec.getParamByName(name);
            if (spec != null) {
                mlkemParameterSpec = spec;
            } else {
                throw new InvalidParameterSpecException("Unknown ML-KEM parameter set: " + name);
            }
        } else {
            throw new InvalidParameterSpecException("Spec is not MLKEMParameterSpec or MLKEMGenParameterSpec");
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

        if (mlkemParameterSpec == null) {
            throw new InvalidParameterSpecException("MLKEMParameterSpec not initialized");
        }

        if (MLKEMParameterSpec.class.isAssignableFrom(paramSpec)) {
            return (T) mlkemParameterSpec;
        }

        if (MLKEMGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T) new MLKEMGenParameterSpec(name);
            }
        }

        throw new InvalidParameterSpecException("Unkonwn parameter spec: " + paramSpec.getName());
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
        return "ML-KEM parameters";
    }
}