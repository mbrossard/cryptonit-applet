package org.cryptonit;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class BERTLV {
    private byte [] buffer;
    private short begin, end, current;

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
