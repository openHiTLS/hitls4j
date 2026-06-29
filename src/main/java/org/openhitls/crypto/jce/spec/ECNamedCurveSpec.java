package org.openhitls.crypto.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.openhitls.crypto.jce.util.ECCurveRegistry;

/**
 * Specification signifying that the curve parameters can also be referred to by name.
 */
public class ECNamedCurveSpec extends java.security.spec.ECParameterSpec {
    private final String name;

    public ECNamedCurveSpec(
        String name,
        EllipticCurve curve,
        ECPoint g,
        BigInteger n) {
        this(name, curve, g, n, BigInteger.ONE);
    }

    public ECNamedCurveSpec(
        String name,
        EllipticCurve curve,
        ECPoint g,
        BigInteger n,
        BigInteger h) {
        super(curve, g, n, h.intValue());
        this.name = name;
    }

    /**
     * Return the name of the curve this specification represents.
     *
     * @return the name of the curve.
     */
    public String getName() {
        return name;
    }

    /**
     * Create parameters for SM2 curve (sm2p256v1).
     */
    public static ECNamedCurveSpec getSM2Curve() {
        BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
        BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
        BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
        BigInteger h = BigInteger.ONE;
        BigInteger gx = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        BigInteger gy = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("sm2p256v1", curve, g, n, h);
    }

    public static ECNamedCurveSpec getNamedCurve(String name) {
        return ECCurveRegistry.getNamedCurve(name);
    }

    public static ECNamedCurveSpec getP256Curve() {
        BigInteger p = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        BigInteger gx = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
        BigInteger gy = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
        BigInteger n = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger h = BigInteger.ONE;

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("secp256r1", curve, g, n, h);
    }

    public static ECNamedCurveSpec getP384Curve() {
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16);
        BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16);
        BigInteger b = new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16);
        BigInteger gx = new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16);
        BigInteger gy = new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16);
        BigInteger h = BigInteger.ONE;

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("secp384r1", curve, g, n, h);
    }

    public static ECNamedCurveSpec getP521Curve() {
        BigInteger p = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger a = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16);
        BigInteger gx = new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16);
        BigInteger gy = new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16);
        BigInteger n = new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16);
        BigInteger h = BigInteger.ONE;

        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, a, b);
        ECPoint g = new ECPoint(gx, gy);

        return new ECNamedCurveSpec("secp521r1", curve, g, n, h);
    }
}
