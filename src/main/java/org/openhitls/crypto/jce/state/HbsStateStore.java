package org.openhitls.crypto.jce.state;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface HbsStateStore {
    HbsStateRecord load(String keyId) throws IOException, GeneralSecurityException;

    void save(HbsStateRecord record) throws IOException, GeneralSecurityException;

    HbsSignCommit withExclusiveSigningState(String keyId, HbsStateTransaction transaction)
            throws IOException, GeneralSecurityException;
}
