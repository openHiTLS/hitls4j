package org.openhitls.crypto.jce.digest;

import java.security.MessageDigestSpi;
import org.openhitls.crypto.core.hash.MessageDigestImpl;

public class MessageDigest extends MessageDigestSpi {
    private final MessageDigestImpl md;
    private final int digestLength;

    protected MessageDigest(String algorithm, int digestLength) {
        this.digestLength = digestLength;
        this.md = new MessageDigestImpl(algorithm);
    }

    @Override
    protected int engineGetDigestLength() {
        return digestLength;
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[1];
        data[0] = input;
        engineUpdate(data, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        md.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return md.doFinalAndReset();
    }

    @Override
    protected void engineReset() {
        md.reset();
    }

    public static final class SHA224 extends MessageDigest {
        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static final class SHA256 extends MessageDigest {
        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static final class SHA384 extends MessageDigest {
        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static final class SHA512 extends MessageDigest {
        public SHA512() {
            super("SHA-512", 64);
        }
    }

    public static final class SM3 extends MessageDigest {
        public SM3() {
            super("SM3", 32);
        }
    }

    public static final class SHA1 extends MessageDigest {
        public SHA1() {
            super("SHA-1", 20);
        }
    }

    public static final class SHA3_224 extends MessageDigest {
        public SHA3_224() {
            super("SHA3-224", 28);
        }
    }

    public static final class SHA3_256 extends MessageDigest {
        public SHA3_256() {
            super("SHA3-256", 32);
        }
    }

    public static final class SHA3_384 extends MessageDigest {
        public SHA3_384() {
            super("SHA3-384", 48);
        }
    }

    public static final class SHA3_512 extends MessageDigest {
        public SHA3_512() {
            super("SHA3-512", 64);
        }
    }
}
