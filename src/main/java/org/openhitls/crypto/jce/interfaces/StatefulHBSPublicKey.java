package org.openhitls.crypto.jce.interfaces;

import java.security.PublicKey;

public interface StatefulHBSPublicKey extends PublicKey, StatefulHBSKey {
    byte[] getPublicData();
}
