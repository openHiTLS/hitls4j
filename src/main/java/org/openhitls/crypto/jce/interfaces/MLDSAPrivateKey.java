package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

public interface MLDSAPrivateKey extends PrivateKey, MLDSAKey{
    byte[] getPrivateData();
}
