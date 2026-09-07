/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.crypto.jce.keyagreement;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.pqc.FrodoKEMImpl;
import org.openhitls.crypto.core.pqc.MLKEMImpl;
import org.openhitls.crypto.core.pqc.McElieceImpl;

public class KEMKeyAgreementResourceTest extends BaseTest {
    @Test
    public void testFrodoKEMInitFailureClosesPreviousImpl() throws Exception {
        FrodoKEMKeyAgreement agreement = new FrodoKEMKeyAgreement();
        TrackingFrodoKEMImpl oldImpl = new TrackingFrodoKEMImpl();
        setField(agreement, "frodoKemImpl", oldImpl);

        expectInvalidKey(() -> agreement.engineInit(new UnsupportedKey(), new SecureRandom()));

        assertTrue(oldImpl.closed);
    }

    @Test
    public void testMLKEMInitFailureClosesPreviousImpl() throws Exception {
        MLKEMKeyAgreement agreement = new MLKEMKeyAgreement();
        TrackingMLKEMImpl oldImpl = new TrackingMLKEMImpl();
        setField(agreement, "mlkemImpl", oldImpl);

        expectInvalidKey(() -> agreement.engineInit(new UnsupportedKey(), new SecureRandom()));

        assertTrue(oldImpl.closed);
    }

    @Test
    public void testMcElieceInitFailureClosesPreviousImpl() throws Exception {
        McElieceKeyAgreement agreement = new McElieceKeyAgreement();
        TrackingMcElieceImpl oldImpl = new TrackingMcElieceImpl();
        setField(agreement, "mcElieceImpl", oldImpl);

        expectInvalidKey(() -> agreement.engineInit(new UnsupportedKey(), new SecureRandom()));

        assertTrue(oldImpl.closed);
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static void expectInvalidKey(InvalidKeyOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected InvalidKeyException");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
    }

    private interface InvalidKeyOperation {
        void run() throws Exception;
    }

    private static final class UnsupportedKey implements Key {
        @Override
        public String getAlgorithm() {
            return "unsupported";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    private static final class TrackingFrodoKEMImpl extends FrodoKEMImpl {
        private boolean closed;

        private TrackingFrodoKEMImpl() {
            super("FrodoKEM-640-SHAKE");
        }

        @Override
        public synchronized void close() {
            closed = true;
            super.close();
        }
    }

    private static final class TrackingMLKEMImpl extends MLKEMImpl {
        private boolean closed;

        private TrackingMLKEMImpl() {
            super("ML-KEM-512");
        }

        @Override
        public synchronized void close() {
            closed = true;
            super.close();
        }
    }

    private static final class TrackingMcElieceImpl extends McElieceImpl {
        private boolean closed;

        private TrackingMcElieceImpl() {
            super("McEliece-6688128");
        }

        @Override
        public synchronized void close() {
            closed = true;
            super.close();
        }
    }
}
