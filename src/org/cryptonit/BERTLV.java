package org.cryptonit;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * @author Mathias Brossard
 */
public class BERTLV {
    private byte [] buffer;
    private short begin, end, current;

    public BERTLV(byte[] buffer, short begin, short end) {
        this.buffer = buffer;
        this.current = this.begin = begin;
        this.end = end;
    }

    public short readLength() {
        short s = this.buffer[this.current];
        this.current += 1;
        return s;
    }

    public static short decodeLength(byte[] buf, short offset) {
        byte b = buf[offset];
        short s = buf[offset];
        if ((b & (byte) 0x80) != 0) {
            offset += 1;

            if (b == (byte) 0x81) {
                s = (short) (0x00FF & buf[offset]);
            } else if (b == (byte) 0x82) {
                s = Util.getShort(buf, offset);
            } else {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        }
        return s;
    }
}
