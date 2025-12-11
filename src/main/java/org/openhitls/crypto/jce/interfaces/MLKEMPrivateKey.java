package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

public interface MLKEMPrivateKey extends PrivateKey, MLKEMKey {
    byte[] getPrivateData();
}