package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface MLDSAPublicKey extends PublicKey, MLDSAKey {
    byte[] getPublicData();
}
