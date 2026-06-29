package org.openhitls.crypto.core.asymmetric;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;

public class ECDSAImplTest extends BaseTest {
    private static final byte[] DEFAULT_SM2_USER_ID = "1234567812345678".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void testResetUserIdReflectsEffectiveSm2Default() {
        ECDSAImpl impl = new ECDSAImpl("sm2p256v1");
        byte[] customUserId = "CustomDomainA".getBytes(StandardCharsets.UTF_8);

        impl.setUserId(customUserId);
        assertArrayEquals(customUserId, impl.getUserId());

        impl.resetUserId();
        assertArrayEquals(DEFAULT_SM2_USER_ID, impl.getUserId());
    }

    @Test
    public void testSetUserIdClearsPreviousUserId() throws Exception {
        ECDSAImpl impl = new ECDSAImpl("sm2p256v1");

        impl.setUserId("CustomDomainA".getBytes(StandardCharsets.UTF_8));
        byte[] previousUserId = getInternalUserId(impl);

        impl.setUserId("CustomDomainB".getBytes(StandardCharsets.UTF_8));

        assertArrayZeroed(previousUserId);
    }

    @Test
    public void testResetUserIdClearsPreviousUserId() throws Exception {
        ECDSAImpl impl = new ECDSAImpl("sm2p256v1");

        impl.setUserId("CustomDomainA".getBytes(StandardCharsets.UTF_8));
        byte[] previousUserId = getInternalUserId(impl);

        impl.resetUserId();

        assertArrayZeroed(previousUserId);
    }

    @Test
    public void testResetUserIdClearsNonSm2State() {
        ECDSAImpl impl = new ECDSAImpl("secp256r1");

        impl.resetUserId();
        assertNull(impl.getUserId());
    }

    private static byte[] getInternalUserId(ECDSAImpl impl) throws Exception {
        Field field = ECDSAImpl.class.getDeclaredField("userId");
        field.setAccessible(true);
        return (byte[]) field.get(impl);
    }

    private static void assertArrayZeroed(byte[] value) {
        assertArrayEquals(new byte[value.length], value);
    }
}
