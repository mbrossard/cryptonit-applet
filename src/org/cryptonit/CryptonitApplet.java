package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacardx.apdu.ExtendedLength;

public class CryptonitApplet extends Applet implements ExtendedLength {
    private OwnerPIN pin;
    private FileIndex index;
    private Key[] keys = null;

    private final static byte PIN_MAX_LENGTH = 8;
    private final static byte PIN_MAX_TRIES  = 5;

    public static final byte INS_GET_DATA =                    (byte) 0xCB;
    public static final byte INS_PUT_DATA =                    (byte) 0xDB;
    public static final byte INS_VERIFY_PIN =                  (byte) 0x20;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;

    public static final short SW_PIN_TRIES_REMAINING = 0x63C0;

    protected CryptonitApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        index = new FileIndex();
        keys  = new Key[(byte) 4];
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
            case INS_PUT_DATA:
                doPutData(apdu);
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

        if((p1 == (byte) 0x04) && (p2 == (byte) 0x00)) {
            final byte [] apt = { (byte) 0x61, (byte) 0x11, (byte) 0x4F, (byte) 0x06,
                                  (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00,
                                  (byte) 0x01, (byte) 0x00, (byte) 0x79, (byte) 0x07,
                                  (byte) 0x4F, (byte) 0x05, (byte) 0xA0, (byte) 0x00,
                                  (byte) 0x00, (byte) 0x03, (byte) 0x08 };
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) apt.length);
            apdu.sendBytesLong(apt, (byte) 0, (short) apt.length);
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

        if(!pin.check(buffer, offset, (byte) lc)) {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
    }

    private void doGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if(p1 != (byte) 0x3F || p2 != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (buf[offset] != (byte) 0x5C) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        switch (buf[(short) (offset + 1)]) {
            case 0x1:
                if (buf[(short) (offset + 2)] == (byte) 0x7E) {
                    byte[] d = index.entries[FileIndex.DISCOVERY].content;
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) d.length);
                    apdu.sendBytesLong(d, (byte) 0, (short) d.length);
                    return;
                }
                break;
            case 0x3:
                if ((buf[(short) (offset + 2)] != (byte) 0x5F)
                        || (buf[(short) (offset + 3)] != (byte) 0xC1)
                        || (buf[(short) (offset + 4)] == (byte) 0x4)
                        || (buf[(short) (offset + 4)] > (byte) 0xA)) {
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
                byte[] d = index.entries[(byte)(buf[(byte)(offset + 4)] - 1)].content;
                if (d != null) {
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) d.length);
                    apdu.sendBytesLong(d, (byte) 0, (short) d.length);
                    return;
                }
                break;
            default:
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void doPutData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if(p1 != (byte) 0x3F || p2 != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != apdu.getIncomingLength() || lc < (byte) 0x06) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (buf[offset] != (byte) 0x5C) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        if((buf[(short) (offset + 1)] != (byte) 0x03)
                || (buf[(short) (offset + 2)] != (byte) 0x5F)
                || (buf[(short) (offset + 3)] != (byte) 0xC1)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte id = (byte) (buf[(short) (offset + 4)] - 1);
        if((id == (byte) 0x03)
                || (id > (byte) 0x0A)) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if(buf[(short) (offset + 5)] != (byte) 0x53) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        offset += 6;
        short l = (short) buf[offset];
        if ((buf[offset] & (byte) 0x80) == 0) {
            offset += 1;
        } else if (buf[offset] == (byte) 0x81) {
            l = (short) (buf[(short) (offset + 1)]);
            offset += 2;
        } else if (buf[offset] == (byte) 0x82) {
            l = Util.getShort(buf, (short) (offset + 1));
            offset += 3;
        } else {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        if((short) (l - offset + apdu.getOffsetCdata()) > lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);            
        }
        index.entries[id].content = new byte[l];
        Util.arrayCopy(buf, offset, index.entries[id].content, (short) 0, l);
    }
    
    private byte keyMapping(byte keyRef) {
        switch (keyRef) {
            case (byte)0x9A:
                return 0;
            case (byte)0x9C:
                return 1;
            case (byte)0x9D:
                return 2;
            case (byte)0x9E:
                return 3;
            default:
                return (byte) 0xFF;
        }
    }

    private void doGenerateKeyPair(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if((p1 != (byte) 0x00) || (keyMapping(p2) == (byte) 0xFF)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        byte [] prefix = new byte[] {
            (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01
        };
        if(Util.arrayCompare(buf, offset, prefix,
                             (byte) 0, (byte) prefix.length) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch (buf[(short) (offset + 4)]) {
            case 0x07:
                doGenRSA(apdu, buf[ISO7816.OFFSET_P2]);
                break;
            case 0x11:
            case 0x14:
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {
        byte [] buf = new byte [271];
        short off = 0;

        byte [] header = new byte [] {
            (byte) 0x7F, (byte) 0x49, (byte) 0x82, (byte) 0x01, (byte) 0x09,
            (byte) 0x81, (byte) 0x82, (byte) 0x01, (byte) 0x00
        };

        Util.arrayCopy(header, (short) 0, buf, (short) 0, (short) header.length);
        off += header.length;
        short l = key.getModulus(buf, off);
        if(l > 0x0100) {
            buf[(short)0x04] = (byte)(l - 0x0100 + 9);
            buf[(short)0x08] = (byte)(l - 0x0100);
        }
        off += l;
        buf[off++] = (byte) 0x82;
        buf[off++] = (byte) 0x03;
        l = key.getExponent(buf, off);
        off += l;
        apdu.setOutgoing();
        apdu.setOutgoingLength(off);
        apdu.sendBytesLong(buf, (byte) 0, off);
    }

    void doGenRSA(APDU apdu, byte keyRef) {
        KeyPair kp = null;
        byte id = keyMapping(keyRef);

        try {
            kp = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        } catch (CryptoException e) {
            if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        if (kp != null) {
            kp.genKeyPair();
            if (keys[id] != null) {
                keys[id].clearKey();
            }
            keys[id] = kp.getPrivate();
            sendRSAPublicKey(apdu, (RSAPublicKey)kp.getPublic());
        }
    }
}
