package org.openhitls.crypto.jce.state;

import java.io.IOException;
import java.security.GeneralSecurityException;

@FunctionalInterface
public interface HbsStateTransaction {
    HbsSignCommit apply(HbsStateRecord current) throws IOException, GeneralSecurityException;
}
