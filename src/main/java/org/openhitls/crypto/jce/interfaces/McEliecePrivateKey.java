package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

public interface McEliecePrivateKey extends PrivateKey, McElieceKey {
    byte[] getPrivateData();
}
