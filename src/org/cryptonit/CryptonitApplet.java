package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacardx.apdu.ExtendedLength;

public class CryptonitApplet extends Applet implements ExtendedLength {
    private OwnerPIN pin;
    private FileIndex index;

    private final static byte PIN_MAX_LENGTH = 8;
    private final static byte PIN_MAX_TRIES  = 5;

    public static final byte INS_GET_DATA =                    (byte) 0xCB;
    public static final byte INS_VERIFY_PIN =                  (byte) 0x20;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;
    protected CryptonitApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        index = new FileIndex();
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptonitApplet(bArray, bOffset, bLength);
    }

    @Override
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        switch (ins) {
            case ISO7816.INS_SELECT:
                doSelect(apdu);
                break;
            case INS_VERIFY_PIN:
                doVerifyPin(apdu);
                break;
            case INS_GET_DATA:
                doGetData(apdu);
                break;
            case INS_GENERATE_ASYMMETRIC_KEYPAIR:
                doGenerateKeyPair(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void doSelect(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if((p1 == 0x04) && (p2 == 0x00)) {
            final byte [] apt = { (byte) 0x61, (byte) 0x11, (byte) 0x4F, (byte) 0x06,
                                  (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00,
                                  (byte) 0x01, (byte) 0x00, (byte) 0x79, (byte) 0x07,
                                  (byte) 0x4F, (byte) 0x05, (byte) 0xA0, (byte) 0x00,
                                  (byte) 0x00, (byte) 0x03, (byte) 0x08 };
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) apt.length);
            apdu.sendBytesLong(apt, (byte) 0, (byte) apt.length);
            return;
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void doVerifyPin(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short offset, lc;

        if(buffer[ISO7816.OFFSET_P1] != 0x00 || buffer[ISO7816.OFFSET_P2] != 0x01) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if ((lc = apdu.setIncomingAndReceive()) != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset = apdu.getOffsetCdata();

        if(!pin.check(buffer, offset, lc)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
    }

    private void doGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if(p1 != (byte)0x3F || p2 != (byte)0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void doGenerateKeyPair(APDU apdu) throws ISOException {
    }
}
