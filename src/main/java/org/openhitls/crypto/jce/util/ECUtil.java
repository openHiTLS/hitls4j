package org.openhitls.crypto.jce.util;

import java.security.spec.*;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public class ECUtil {
    /**
     * Identifies the curve name from ECParameterSpec
     */
    public static String getCurveName(ECParameterSpec params) {
        if (params == null) {
            throw new IllegalArgumentException("ECParameterSpec cannot be null");
        }

        // First check if it's already a named curve
        if (params instanceof ECNamedCurveSpec) {
            String curveName = ECCurveRegistry.canonicalName(((ECNamedCurveSpec)params).getName());
            ECNamedCurveSpec namedCurve = ECCurveRegistry.getNamedCurve(curveName);
            if (!matches(params, namedCurve)) {
                throw new IllegalArgumentException("Named curve parameters do not match " + curveName);
            }
            return curveName;
        }

        ECField field = params.getCurve().getField();
        if (!(field instanceof ECFieldFp)) {
            throw new IllegalArgumentException("Only prime-field EC curves are supported");
        }

        for (ECNamedCurveSpec namedCurve : ECCurveRegistry.getCanonicalCurves()) {
            if (matches(params, namedCurve)) {
                return namedCurve.getName();
            }
        }

        throw new IllegalArgumentException("Unsupported curve parameters");
    }

    private static boolean matches(ECParameterSpec params, ECParameterSpec named) {
        ECField paramsField = params.getCurve().getField();
        ECField namedField = named.getCurve().getField();
        if (!(paramsField instanceof ECFieldFp) || !(namedField instanceof ECFieldFp)) {
            return false;
        }
        return ((ECFieldFp) paramsField).getP().equals(((ECFieldFp) namedField).getP())
                && params.getCurve().getA().equals(named.getCurve().getA())
                && params.getCurve().getB().equals(named.getCurve().getB())
                && params.getGenerator().equals(named.getGenerator())
                && params.getOrder().equals(named.getOrder())
                && params.getCofactor() == named.getCofactor();
    }

    /**
     * Converts field size in bits to bytes, rounding up
     */
    public static int getFieldSize(ECParameterSpec params) {
        return (params.getCurve().getField().getFieldSize() + 7) / 8;
    }

    /**
     * Pads or trims a byte array to the specified length
     */
    public static byte[] padOrTrim(byte[] input, int length) {
        if (input.length == length) {
            return input;
        }
        
        byte[] result = new byte[length];
        if (input.length > length) {
            // Trim from the left (preserve least significant bytes)
            System.arraycopy(input, input.length - length, result, 0, length);
        } else {
            // Pad with zeros on the left
            System.arraycopy(input, 0, result, length - input.length, input.length);
        }
        return result;
    }
}
