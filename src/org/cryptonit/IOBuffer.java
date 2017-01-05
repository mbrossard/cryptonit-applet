package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * @author Mathias Brossard
 */

public class IOBuffer {
    private FileIndex index = null;
    private byte[] buffer = null;

    private short[] shorts = null;
    final private byte SIZE   = 0x0;
    final private byte PATH   = 0x1;
    final private byte OFFSET = 0x2;

    private boolean[] bools = null;
    final private byte isLOADED = 0x0;
    final private byte isFILE   = 0x1;

    public void clear() {
        this.bools[isLOADED] = false;
    }

    public boolean isLoaded() {
        return this.bools[isLOADED];
    }

    public IOBuffer(FileIndex index) {
        this.index = index;
        this.bools = JCSystem.makeTransientBooleanArray((short) 2,
                JCSystem.CLEAR_ON_DESELECT);
        this.buffer = JCSystem.makeTransientByteArray((short) 256,
                JCSystem.CLEAR_ON_DESELECT);
        this.shorts = JCSystem.makeTransientShortArray((short) 3,
                JCSystem.CLEAR_ON_DESELECT);
    }

    public void sendBuffer(byte[] buf, short length, APDU apdu) {
        short le = apdu.setOutgoing(), r = 0;

        if (le == 0) {
            le = (short) (APDU.getOutBlockSize() - 2);
        }

        if (le > length) {
            le = length;
        }

        if (le < length) {
            r = (short) (length - le);
            if (r > (short) this.buffer.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            this.bools[isLOADED] = true;
            this.bools[isFILE]   = false;
            this.shorts[SIZE]    = r;
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(buf, (short) 0, le);

        if (r > 0) {
            if (r >= (short) (APDU.getOutBlockSize() - 2)) {
                r = 0;
            }
            Util.arrayCopy(buf, le, this.buffer, (short) 0, r);
            ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | r));
        } else {
            clear();
        }
    }

    public void sendFile(short id, APDU apdu, short offset) {
        byte[] d = index.entries[id].content;
        if (d == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        short le = apdu.setOutgoing(), r = 0;
        if (le == 0) {
            le = (short) (APDU.getOutBlockSize() - 2);
        }

        if ((short) (le + offset) > (short) d.length) {
            le = (short) (d.length - offset);
        }

        if ((short) (le + offset) < (short) d.length) {
            r = (short) (d.length - (le + offset));
            this.bools[isLOADED] = true;
            this.bools[isFILE]   = true;
            this.shorts[OFFSET]  = (short) (le + offset);
            this.shorts[PATH]    = id;
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(d, offset, le);

        if (r > 0) {
            if (r >= (short) (APDU.getOutBlockSize() - 2)) {
                r = 0;
            }
            ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | r));
        } else {
            clear();
        }
    }

    public void getResponse(APDU apdu) {
        if (!this.bools[isLOADED]) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        if (this.bools[isFILE]) {
            sendFile(this.shorts[PATH], apdu, this.shorts[OFFSET]);
        } else {
            sendBuffer(this.buffer, this.shorts[SIZE], apdu);
        }
    }

    public void receiveBuffer(byte[] buf, short offset, short length) {
        if (this.bools[isLOADED]) {
            if (this.bools[isFILE]) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            Util.arrayCopy(buf, offset, this.buffer, this.shorts[SIZE], length);
            this.shorts[SIZE] += length;
        } else {
            Util.arrayCopy(buf, offset, this.buffer, (short) 0, length);
            this.shorts[SIZE] = length;
            this.bools[isLOADED] = true;
            this.bools[isFILE] = false;
        }
    }

    public byte[] retrieveBuffer(byte[] buf, short offset, short length) {
        if (!this.bools[isLOADED] || this.bools[isFILE]) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short l = (short) (this.shorts[SIZE] + length);
        byte[] r = new byte[l];

        Util.arrayCopy(this.buffer, (short) 0, r, (short) 0, this.shorts[SIZE]);
        Util.arrayCopy(buf, offset, r, this.shorts[SIZE], length);

        this.bools[isLOADED] = false;
        return r;
    }
}
