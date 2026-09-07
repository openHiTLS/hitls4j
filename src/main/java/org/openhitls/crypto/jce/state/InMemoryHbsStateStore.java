/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
