package org.openhitls.crypto.jce.interfaces;

import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

public interface McElieceKey {
    McElieceParameterSpec getParams();
}
