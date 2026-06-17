package org.openhitls.crypto.jce.interfaces;

import java.security.PrivateKey;

import org.openhitls.crypto.jce.state.HbsStateStore;

public interface StatefulHBSPrivateKey extends PrivateKey, StatefulHBSKey {
    byte[] getPrivateData();

    HbsStateStore getStateStore();

    String getStateKeyId();

    void enableUnsafeInMemorySigning();

    void disableUnsafeInMemorySigning();

    boolean isUnsafeInMemorySigningEnabled();
}
