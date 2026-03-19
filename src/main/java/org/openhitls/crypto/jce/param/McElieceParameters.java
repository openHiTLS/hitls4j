package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.McElieceGenParameterSpec;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class McElieceParameters extends AlgorithmParametersSpi {
    private McElieceParameterSpec mcelieceParameterSpec;
    private String name;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("Parameter specification cannot be null");
        }

        if (paramSpec instanceof McElieceParameterSpec) {
            mcelieceParameterSpec = (McElieceParameterSpec) paramSpec;
        } else if (paramSpec instanceof McElieceGenParameterSpec) {
            name = ((McElieceGenParameterSpec) paramSpec).getName();
            McElieceParameterSpec spec = McElieceParameterSpec.getParamByName(name);
            if (spec != null) {
                mcelieceParameterSpec = spec;
            } else {
                throw new InvalidParameterSpecException("Unknown Classic McEliece parameter set: " + name);
            }
        } else {
            throw new InvalidParameterSpecException("Spec is not McElieceParameterSpec or McElieceGenParameterSpec");
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

        if (mcelieceParameterSpec == null) {
            throw new InvalidParameterSpecException("McElieceParameterSpec not initialized");
        }

        if (McElieceParameterSpec.class.isAssignableFrom(paramSpec)) {
            return (T) mcelieceParameterSpec;
        }

        if (McElieceGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T) new McElieceGenParameterSpec(name);
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
        return "Classic McEliece parameters";
    }
}
