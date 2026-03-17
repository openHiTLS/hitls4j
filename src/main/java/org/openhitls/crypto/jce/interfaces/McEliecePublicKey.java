package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface McEliecePublicKey extends PublicKey, McElieceKey {
    byte[] getPublicData();
}
