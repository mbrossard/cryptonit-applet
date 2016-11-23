package org.cryptonit;

import javacard.framework.JCSystem;

public class IOBuffer {
    private FileIndex index = null;
    private byte [] buffer = null;

    private short [] shorts = null;
    final private byte SIZE = 0x0;
    final private byte PATH = 0x1;
    final private byte OFFSET = 0x2;

    private boolean [] bools = null;
    final private byte isLOADED = 0x0;
    final private byte isFILE   = 0x1;

    public IOBuffer(FileIndex index) {
        this.index = index;
        this.bools = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        this.buffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        this.shorts = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
    }

    public void sendBuffer(byte[] buf, short length, APDU apdu) {
        short le = apdu.setOutgoing();

        if(le == 0) {
            le = apdu.getOutBlockSize();
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(buf, (short) 0, le);
    }
}
