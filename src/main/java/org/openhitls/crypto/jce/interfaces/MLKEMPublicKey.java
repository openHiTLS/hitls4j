package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface MLKEMPublicKey extends PublicKey, MLKEMKey {
    byte[] getPublicData();
}
