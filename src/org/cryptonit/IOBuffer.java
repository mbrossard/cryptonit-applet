package org.cryptonit;

import javacard.framework.JCSystem;

public class IOBuffer {
    private FileIndex index = null;
    private byte [] buffer = null;

    private short [] shorts = null;
    private boolean [] bools = null;
    final private byte isLOADED = 0x0;
    final private byte isFILE   = 0x1;

    public IOBuffer(FileIndex index) {
        this.index = index;
        this.bools = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        this.buffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        this.shorts = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
    }
}
