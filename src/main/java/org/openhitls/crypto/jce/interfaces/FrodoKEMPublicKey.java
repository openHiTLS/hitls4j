package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface FrodoKEMPublicKey extends PublicKey, FrodoKEMKey {
    byte[] getPublicData();
}
