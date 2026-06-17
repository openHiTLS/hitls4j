package org.openhitls.crypto.jce.state;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public final class InMemoryHbsStateStore implements HbsStateStore {
    private final Map<String, HbsStateRecord> records = new HashMap<>();

    @Override
    public synchronized HbsStateRecord load(String keyId) throws IOException {
        HbsStateRecord record = records.get(keyId);
        if (record == null) {
            throw new FileNotFoundException("HBS state not found: " + keyId);
        }
        return record;
    }

    @Override
    public synchronized void save(HbsStateRecord record) throws GeneralSecurityException {
        HbsStateRecord current = records.get(record.getKeyId());
        if (current != null && record.getVersion() <= current.getVersion()) {
            throw new GeneralSecurityException("Refusing to roll back HBS state");
        }
        records.put(record.getKeyId(), record);
    }

    @Override
    public synchronized HbsSignCommit withExclusiveSigningState(String keyId, HbsStateTransaction transaction)
            throws IOException, GeneralSecurityException {
        HbsStateRecord current = load(keyId);
        HbsSignCommit commit = transaction.apply(current);
        if (!keyId.equals(commit.getUpdatedState().getKeyId())) {
            throw new GeneralSecurityException("HBS state transaction changed keyId");
        }
        save(commit.getUpdatedState());
        return commit;
    }
}
