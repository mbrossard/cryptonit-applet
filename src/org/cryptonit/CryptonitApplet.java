package org.cryptonit;

import javacard.framework.*;

public class CryptonitApplet extends Applet {
    protected CryptonitApplet() {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptonitApplet();
    }

    @Override
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
		if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
}
