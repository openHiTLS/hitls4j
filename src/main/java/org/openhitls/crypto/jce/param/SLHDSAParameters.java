package org.openhitls.crypto.jce.param;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAParameters extends AlgorithmParametersSpi{
    private SLHDSAParameterSpec slhdsaParameterSpec;

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException("paramSpec is null");
        }

        if (SLHDSAParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (slhdsaParameterSpec == null) {
                throw new InvalidParameterSpecException("SLHDSAParameterSpec not initialized");
            }
            return (T)slhdsaParameterSpec;
        }

        throw new InvalidParameterSpecException("Unknow parameter spec: " + paramSpec.getName());
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof SLHDSAParameterSpec) {
            slhdsaParameterSpec = (SLHDSAParameterSpec)paramSpec;
        } else {
            throw new InvalidParameterSpecException("Spec is not SLHDSAParameterSpec");
        }
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
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        throw new IOException("Not implemented");
    }

    @Override
    protected String engineToString() {
        return "SLH-DSA parameters";
    }
    
}
