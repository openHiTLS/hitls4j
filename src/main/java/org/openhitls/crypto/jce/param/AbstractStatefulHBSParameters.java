package org.openhitls.crypto.jce.param;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public abstract class AbstractStatefulHBSParameters<T extends AlgorithmParameterSpec> extends AlgorithmParametersSpi {
    private T spec;

    protected abstract Class<T> specClass();

    protected abstract String algorithmName();

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!specClass().isInstance(paramSpec)) {
            throw new InvalidParameterSpecException("Spec is not " + specClass().getSimpleName());
        }
        spec = specClass().cast(paramSpec);
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
    protected <P extends AlgorithmParameterSpec> P engineGetParameterSpec(Class<P> paramSpec)
            throws InvalidParameterSpecException {
        if (spec == null) {
            throw new InvalidParameterSpecException(algorithmName() + " parameters not initialized");
        }
        if (paramSpec.isAssignableFrom(specClass())) {
            return paramSpec.cast(spec);
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
        return algorithmName() + " parameters";
    }
}
