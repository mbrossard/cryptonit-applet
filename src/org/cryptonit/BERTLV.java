package org.cryptonit;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * @author Mathias Brossard
 */

public class BERTLV {
    final private byte [] buffer;
    final private short begin;
    final private short end;
    private short current;

    public BERTLV(byte[] buffer, short begin, short end) {
        this.buffer = buffer;
        this.begin = begin;
        this.current = begin;
        this.end = end;
    }

    public short getOffset() {
        return current;
    }

    public short rewind() {
        current = begin;
        return current;
    }

    public short skip(short offset) {
        if (((short) (current + offset)) >= end) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }        
        return current += offset;
    }

    public short readLength() {
        if (current >= end) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte b = buffer[current];
        short s = (short) buffer[current];
        current += 1;

        if ((b & (byte) 0x80) != 0) {
            if (b == (byte) 0x81) {
                if (current >= end) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                s = (short) (0x00FF & buffer[current]);
                this.current += 1;
            } else if (b == (byte) 0x82) {
                if (current >= (short) (end + 1)) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                s = Util.getShort(buffer, current);
                this.current += 2;
            } else {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }
        return s;
    }

    public static short decodeLength(byte[] buf, short offset) {
        short off = offset;
        byte b = buf[off];
        short s = buf[off];
        if ((b & (byte) 0x80) != 0) {
            off += 1;

            if (b == (byte) 0x81) {
                s = (short) (0x00FF & buf[off]);
            } else if (b == (byte) 0x82) {
                s = Util.getShort(buf, off);
            } else {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        }
        return s;
    }
}
