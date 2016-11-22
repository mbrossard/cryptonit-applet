package org.cryptonit;

import javacard.framework.JCSystem;

public class IOBuffer {
    private FileIndex index = null;
    private byte [] buffer = null;

    private boolean [] bools = null;
    public IOBuffer(FileIndex index) {
        this.index = index;
        this.bools = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        this.buffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
    }
}
