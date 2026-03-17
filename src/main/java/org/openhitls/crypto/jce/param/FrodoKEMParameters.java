package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.FrodoKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class FrodoKEMParameters extends AlgorithmParametersSpi {
    private FrodoKEMParameterSpec frodoKemParameterSpec;
    private String name;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("Parameter specification cannot be null");
        }

        if (paramSpec instanceof FrodoKEMParameterSpec) {
            frodoKemParameterSpec = (FrodoKEMParameterSpec) paramSpec;
        } else if (paramSpec instanceof FrodoKEMGenParameterSpec) {
            name = ((FrodoKEMGenParameterSpec) paramSpec).getName();
            FrodoKEMParameterSpec spec = FrodoKEMParameterSpec.getParamByName(name);
            if (spec != null) {
                frodoKemParameterSpec = spec;
            } else {
                throw new InvalidParameterSpecException("Unknown FrodoKEM parameter set: " + name);
            }
        } else {
            throw new InvalidParameterSpecException("Spec is not FrodoKEMParameterSpec or FrodoKEMGenParameterSpec");
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

        if (frodoKemParameterSpec == null) {
            throw new InvalidParameterSpecException("FrodoKEMParameterSpec not initialized");
        }

        if (FrodoKEMParameterSpec.class.isAssignableFrom(paramSpec)) {
            return (T) frodoKemParameterSpec;
        }

        if (FrodoKEMGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T) new FrodoKEMGenParameterSpec(name);
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
        return "FrodoKEM parameters";
    }
}
