package org.cryptonit;

import javacard.framework.JCSystem;

public class IOBuffer {
    private FileIndex index = null;
    private byte [] buffer = null;

    public IOBuffer(FileIndex index) {
        this.index = index;
        this.buffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
    }
}
