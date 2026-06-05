package org.openhitls.crypto.jce.cert;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SelfSignedCertificateTest {
    private static final byte[] SHA256_WITH_RSA_ALGORITHM = derSequence(
            derOid("1.2.840.113549.1.1.11"),
            derNull());

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testHitlsSelfSignedRsaCertificateVerifiesItself() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] publicKeyInfo = keyPair.getPublic().getEncoded();
        assertNotNull("RSA public key must provide X.509 SubjectPublicKeyInfo encoding", publicKeyInfo);

        byte[] tbsCertificate = createTbsCertificate(publicKeyInfo);

        Signature signature = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(tbsCertificate);
        byte[] signatureBytes = signature.sign();

        byte[] certificateBytes = derSequence(
                tbsCertificate,
                SHA256_WITH_RSA_ALGORITHM,
                derBitString(signatureBytes));

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(certificateBytes));

        assertEquals("SHA256withRSA", certificate.getSigAlgName());
        assertArrayEquals(publicKeyInfo, certificate.getPublicKey().getEncoded());
        certificate.verify(certificate.getPublicKey(), HiTls4jProvider.PROVIDER_NAME);
    }

    private static byte[] createTbsCertificate(byte[] publicKeyInfo) {
        byte[] version = derExplicit(0, derInteger(BigInteger.valueOf(2)));
        byte[] serialNumber = derInteger(BigInteger.ONE);
        byte[] name = derName("hitls4j-self-signed");
        byte[] validity = derSequence(
                derUtcTime(new Date(System.currentTimeMillis() - 60_000L)),
                derUtcTime(new Date(System.currentTimeMillis() + 86_400_000L)));

        return derSequence(
                version,
                serialNumber,
                SHA256_WITH_RSA_ALGORITHM,
                name,
                validity,
                name,
                publicKeyInfo);
    }

    private static byte[] derName(String commonName) {
        return derSequence(derSet(derSequence(
                derOid("2.5.4.3"),
                derUtf8String(commonName))));
    }

    private static byte[] derSequence(byte[]... values) {
        return der(0x30, concat(values));
    }

    private static byte[] derSet(byte[]... values) {
        return der(0x31, concat(values));
    }

    private static byte[] derExplicit(int tagNumber, byte[] value) {
        return der(0xa0 + tagNumber, value);
    }

    private static byte[] derInteger(BigInteger value) {
        return der(0x02, value.toByteArray());
    }

    private static byte[] derOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return der(0x06, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        int length = 1;
        long remaining = value;
        while ((remaining >>= 7) > 0) {
            length++;
        }
        for (int i = length - 1; i >= 0; i--) {
            int b = (int) ((value >> (7 * i)) & 0x7f);
            if (i != 0) {
                b |= 0x80;
            }
            out.write(b);
        }
    }

    private static byte[] derNull() {
        return der(0x05, new byte[0]);
    }

    private static byte[] derUtf8String(String value) {
        try {
            return der(0x0c, value.getBytes("UTF-8"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] derUtcTime(Date date) {
        SimpleDateFormat format = new SimpleDateFormat("yyMMddHHmmss'Z'");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return der(0x17, format.format(date).getBytes("US-ASCII"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] derBitString(byte[] value) {
        byte[] content = new byte[value.length + 1];
        System.arraycopy(value, 0, content, 1, value.length);
        return der(0x03, content);
    }

    private static byte[] der(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }

        int bytes = 0;
        int value = length;
        while (value > 0) {
            bytes++;
            value >>= 8;
        }
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((length >> (8 * i)) & 0xff);
        }
    }

    private static byte[] concat(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            length += value.length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }
}
