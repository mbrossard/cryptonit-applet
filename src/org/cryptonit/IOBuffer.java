package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


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

        if(le < length) {
            short l = (short) (length - le);
            if(l > (short) this.buffer.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopy(buf, (short) le, this.buffer, (short) 0, l);
            this.bools[isLOADED] = true;
            this.bools[isFILE] = false;
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(buf, (short) 0, le);
    }
}
