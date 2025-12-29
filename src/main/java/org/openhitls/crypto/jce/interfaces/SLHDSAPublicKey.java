package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface SLHDSAPublicKey extends SLHDSAKey, PublicKey{
    byte[] getPublicData();
}
