package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class CryptonitApplet extends Applet {
    private OwnerPIN pin;

    private final static byte PIN_MAX_LENGTH = 8;
    private final static byte PIN_MAX_TRIES  = 5;

    protected CryptonitApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptonitApplet(bArray, bOffset, bLength);
    }

    @Override
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

		if (apdu.isISOInterindustryCLA()) {
            if (ins == ISO7816.INS_SELECT) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
}
