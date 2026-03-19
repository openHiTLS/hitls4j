package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

public interface FrodoKEMPrivateKey extends PrivateKey, FrodoKEMKey {
    byte[] getPrivateData();
}
