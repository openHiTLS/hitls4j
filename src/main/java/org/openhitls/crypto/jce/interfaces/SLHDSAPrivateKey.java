package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

public interface SLHDSAPrivateKey extends SLHDSAKey, PrivateKey {
    byte[] getPrivateData();
}
