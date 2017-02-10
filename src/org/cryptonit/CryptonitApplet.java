package org.cryptonit;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPublicKey;
import javacard.security.RandomData;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * @author Mathias Brossard
 */
public class CryptonitApplet extends Applet implements ExtendedLength {

    private final OwnerPIN pin;
    private final OwnerPIN mgmt_counter;
    private final FileIndex index;
    private Key[] keys = null;
    private Key mgmt_key = null;
    private byte[] challenge = null;
    private boolean[] authenticated = null;
    private Cipher rsa_cipher = null;
    private Signature ec_signature = null;
    private RandomData random = null;
    private IOBuffer io = null;

    private final static byte PIN_MAX_LENGTH = 8;
    private final static byte PIN_MAX_TRIES  = 5;
    private final static byte MGMT_MAX_TRIES = 3;

    public static final byte INS_GET_DATA                    = (byte) 0xCB;
    public static final byte INS_GET_RESPONSE                = (byte) 0xC0;
    public static final byte INS_PUT_DATA                    = (byte) 0xDB;
    public static final byte INS_VERIFY_PIN                  = (byte) 0x20;
    public static final byte INS_GENERAL_AUTHENTICATE        = (byte) 0x87;
    public static final byte INS_CHANGE_REFERENCE_DATA       = (byte) 0x24;
    public static final byte INS_GENERATE_ASYMMETRIC_KEYPAIR = (byte) 0x47;

    public static final short SW_PIN_TRIES_REMAINING           = 0x63C0;
    public static final short SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;

    protected CryptonitApplet(byte[] bArray, short bOffset, byte bLength) {
        mgmt_key = KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
                KeyBuilder.LENGTH_DES3_3KEY, false);
        ((DESKey) mgmt_key).setKey(new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        }, (short) 0);
        mgmt_counter = new OwnerPIN(MGMT_MAX_TRIES, (byte) 4);
        mgmt_counter.update(new byte[]{0x00, 0x00, 0x00, 0x00}, (short) 0, (byte) 4);

        challenge = JCSystem.makeTransientByteArray((short) 8,
                JCSystem.CLEAR_ON_DESELECT);

        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        pin.update(new byte[]{
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        }, (short) 0, (byte) 8);

        index = new FileIndex();
        keys = new Key[(byte) 4];
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        authenticated = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        rsa_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        try {
            ec_signature = Signature.getInstance((byte) 33, false);
        } catch (Exception e) {
        }
        io = new IOBuffer(index);
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
            case INS_CHANGE_REFERENCE_DATA:
                doChangePIN(apdu);
                break;
            case INS_GET_DATA:
                doGetData(apdu);
                break;
            case INS_GET_RESPONSE:
                io.getResponse(apdu);
                break;
            case INS_PUT_DATA:
                doPutData(apdu);
                break;
            case INS_GENERATE_ASYMMETRIC_KEYPAIR:
                doGenerateKeyPair(apdu);
                break;
            case INS_GENERAL_AUTHENTICATE:
                doGeneralAuthenticate(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void doSelect(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        final byte[] apt = {
            /* Application property template */
            (byte) 0x61, (byte) 0x16,
            /* - Application identifier of application */
            (byte) 0x4F, (byte) 0x0B,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08,
            (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01,
            (byte) 0x00,
            /* - Coexistent tag allocation authority */
            (byte) 0x79, (byte) 0x07,
            /*   - Application identifier */
            (byte) 0x4F, (byte) 0x05,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08
        };

        if ((p1 == (byte) 0x04) && (p2 == (byte) 0x00)) {
            short l = apdu.setIncomingAndReceive();
            short offset = apdu.getOffsetCdata();

            final byte[] aid1 = {
                (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08
            };
            final byte[] aid2 = {
                (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03,
                (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x10,
                (byte) 0x00
            };
            if (((l == (short) aid1.length)
                    && (Util.arrayCompare(buf, offset, aid1, (byte) 0, (byte) aid1.length) == 0))
                    || ((l == (short) aid2.length)
                    && (Util.arrayCompare(buf, offset, aid2, (byte) 0, (byte) aid2.length) == 0))) {
                io.sendBuffer(apt, (short) apt.length, apdu);
                return;
            }
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void doVerifyPin(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset, lc = apdu.setIncomingAndReceive();

        if ((p1 != (byte) 0x00 && p1 != (byte) 0xFF) || (p2 != (byte) 0x80)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (p1 == (byte) 0xFF) {
            authenticated[0] = false;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        if ((lc != apdu.getIncomingLength()) || lc != (short) 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        offset = apdu.getOffsetCdata();

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
        }

        // Check the PIN.
        if (!pin.check(buf, offset, (byte) lc)) {
            // Authentication failed
            authenticated[0] = false;
            ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING
                    | pin.getTriesRemaining()));
        } else {
            // Authentication successful
            authenticated[0] = true;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }

    private void doChangePIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short off, lc = apdu.setIncomingAndReceive();

        if (p1 != (byte) 0x00 || (p2 != (byte) 0x80)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
        }
        if ((lc != apdu.getIncomingLength()) || lc != (short) 16) {
            ISOException.throwIt((short) 0x6480);
        }
        off = apdu.getOffsetCdata();

        for (short i = 0; i < (short) 16; i++) {
            if (((buf[(short) (i + off)] < 0x30)
                    || (buf[(short) (i + off)] > 0x39))
                    && (buf[(short) (i + off)] != 0xFF)) {
                ISOException.throwIt((short) 0x6480);
            }
        }
        if (!pin.check(buf, off, (byte) 8)) {
            // Authentication failed
            authenticated[0] = false;
            ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING
                    | pin.getTriesRemaining()));
        }

        pin.update(buf, (short) (off + 8), (byte) 8);
    }

    private void doGetData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if (p1 != (byte) 0x3F || p2 != (byte) 0xFF) {
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
                    io.sendFile(FileIndex.DISCOVERY, apdu, (short) 0);
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
                byte id = (byte) (buf[(byte) (offset + 4)] - 1);
                if (((id == (byte) 0x2) || (id == (byte) 0x7)
                        || (id == (byte) 0x8)) && authenticated[0] == false) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                io.sendFile(id, apdu, (short) 0);
                return;
            default:
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void doPutData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        byte cla = buf[ISO7816.OFFSET_CLA];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();

        if (p1 != (byte) 0x3F || p2 != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if ((cla != 0x0) && (cla != 0x10)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (authenticated[0] == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (io.isLoaded()) {
            io.receiveFile(buf, offset, lc);
            if (cla == 0x00) {
                io.clear();
            }
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        if (lc != apdu.getIncomingLength() || lc < (byte) 0x06) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte id;
        if (buf[offset] == (byte) 0x5C) {
            if ((buf[(short) (offset + 1)] != (byte) 0x03)
                    || (buf[(short) (offset + 2)] != (byte) 0x5F)
                    || (buf[(short) (offset + 3)] != (byte) 0xC1)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            id = (byte) (buf[(short) (offset + 4)] - 1);
            if ((id == (byte) 0x03)
                    || (id > (byte) 0x0A)) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
            if (buf[(short) (offset + 5)] != (byte) 0x53) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            offset += 5;
        } else if (buf[offset] == (byte) 0x7E) {
            id = FileIndex.DISCOVERY;
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            return;
        }

        short l = (short) buf[offset];
        short off = (short) (offset + 1);
        if ((buf[off] & (byte) 0x80) == 0) {
            off += 1;
        } else if (buf[off] == (byte) 0x81) {
            l = (short) (buf[(short) (off + 1)]);
            off += 2;
        } else if (buf[off] == (byte) 0x82) {
            l = Util.getShort(buf, (short) (off + 1));
            off += 3;
        } else {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        io.createFile(id, (short) (l + (off - offset)));
        io.receiveFile(buf, offset, (short) (lc - (offset - apdu.getOffsetCdata())));

        if (cla == 0x00) {
            io.clear();
        }
    }

    private byte keyMapping(byte keyRef) {
        switch (keyRef) {
            case (byte) 0x9A:
                return 0;
            case (byte) 0x9C:
                return 1;
            case (byte) 0x9D:
                return 2;
            case (byte) 0x9E:
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

        if ((p1 != (byte) 0x00) || (keyMapping(p2) == (byte) 0xFF)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (authenticated[0] == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] prefix = new byte[]{
            (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01
        };
        if (Util.arrayCompare(buf, offset, prefix,
                (byte) 0, (byte) prefix.length) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch (buf[(short) (offset + 4)]) {
            case 0x07:
                doGenRSA(apdu, buf[ISO7816.OFFSET_P2]);
                break;
            case 0x11:
                if (ec_signature == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                doGenEC(apdu, buf[ISO7816.OFFSET_P2], (short) 256);
                break;
            case 0x14:
                if (ec_signature == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                doGenEC(apdu, buf[ISO7816.OFFSET_P2], (short) 384);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void sendRSAPublicKey(APDU apdu, RSAPublicKey key) {
        // T:0x7F,0x49 L:0x82,0x01,09 (265)
        // - T:0x81 L:0x82,0x01,0x00  (256) V:[RSA Modulus 256 bytes]
        // - T:0x82 L:0x03              (3) V:[RSA Exponent  3 bytes]
        short off = 0;
        byte[] buf = new byte[271];
        byte[] header = new byte[]{
            (byte) 0x7F, (byte) 0x49, (byte) 0x82, (byte) 0x01, (byte) 0x09,
            (byte) 0x81, (byte) 0x82, (byte) 0x01, (byte) 0x00
        };

        Util.arrayCopy(header, (short) 0, buf, (short) 0, (short) header.length);
        off += header.length;
        short l = key.getModulus(buf, off);
        if (l > 0x0100) {
            buf[(short) 0x04] = (byte) (l - 0x0100 + 9);
            buf[(short) 0x08] = (byte) (l - 0x0100);
        }
        off += l;
        buf[off++] = (byte) 0x82;
        buf[off++] = (byte) 0x03;
        off += key.getExponent(buf, off);
        io.sendBuffer(buf, off, apdu);
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
            sendRSAPublicKey(apdu, (RSAPublicKey) kp.getPublic());
        }
    }

    private void sendECPublicKey(APDU apdu, ECPublicKey key) {
        // T:0x7F,0x49 L:0x43          (67)
        // - T:0x86 L:0x41             (65) V:[EC Point     65 bytes]
        byte buf[] = new byte[70];
        Util.arrayCopy(new byte[]{
            (byte) 0x7F, (byte) 0x49, (byte) 0x43, (byte) 0x86, (byte) 0x41
        }, (short) 0, buf, (short) 0, (short) 5);
        short l = key.getW(buf, (short) 5);
        io.sendBuffer(buf, (short) buf.length, apdu);
    }

    void doGenEC(APDU apdu, byte keyRef, short size) {
        KeyPair kp = null;
        byte id = keyMapping(keyRef);
        try {
            kp = new KeyPair(KeyPair.ALG_EC_FP, size);
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
            sendECPublicKey(apdu, (ECPublicKey) kp.getPublic());
        }
    }

    public static short lengthLength(short l) {
        return (short) ((l < 128) ? 1 : ((l < 256) ? 2 : 3));
    }

    public static short getTag(byte[] buf, short off, short length, byte tag) {
        short end = (short) (off + length - 1);

        while ((off < end) && (buf[off] != tag)) {
            short l = BERTLV.decodeLength(buf, (short) (off + 1));
            off += lengthLength(l) + l + 1;
        }
        return off;
    }

    private void doGeneralAuthenticate(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if ((p1 == (byte) 0x07 || p1 == (byte) 0x11 || p1 == (byte) 0x14)
                && (keyMapping(p2) != (byte) 0xFF)) {
            doPrivateKeyOperation(apdu);
        } else if ((p1 == (byte) 0x00 || p1 == (byte) 0x03)
                && (p2 == (byte) 0x9B)) {
            doAuthenticate(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void doAuthenticate(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();
        if ((lc == (short) 4) && (Util.arrayCompare(buf, offset, new byte[]{
            (byte) 0x7C, (byte) 0x02, (byte) 0x80, (byte) 0x00
        }, (short) 0, (short) 4) == (short) 0)) {
            Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
            byte[] out = new byte[12];
            Util.arrayCopy(new byte[]{
                (byte) 0x7C, (byte) 0x0A, (byte) 0x80, (byte) 0x08
            }, (short) 0, out, (short) 0, (short) 4);

            random.generateData(challenge, (short) 0, (short) 8);
            cipher.init(mgmt_key, Cipher.MODE_ENCRYPT);
            cipher.doFinal(challenge, (short) 0, (short) 8, out, (short) 4);
            io.sendBuffer(out, (short) 12, apdu);
        } else if ((lc == (short) 22) && (Util.arrayCompare(buf, offset, new byte[]{
            (byte) 0x7C, (byte) 0x14, (byte) 0x80, (byte) 0x08
        }, (short) 0, (short) 4) == (short) 0)) {
            if (mgmt_counter.getTriesRemaining() == 0) {
                ISOException.throwIt(SW_AUTHENTICATION_METHOD_BLOCKED);
            }
            if (Util.arrayCompare(buf, (short) (offset + 4),
                    challenge, (short) 0, (short) 8) == 0) {
                mgmt_counter.resetAndUnblock();
                authenticated[0] = true;

                if ((buf[(short) (offset + 0x0C)] == (byte) 0x81)
                        && (buf[(short) (offset + 0x0D)] == (byte) 0x08)) {
                    Cipher cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
                    byte[] out = new byte[12];
                    Util.arrayCopy(new byte[]{
                        (byte) 0x7C, (byte) 0x0A, (byte) 0x82, (byte) 0x08
                    }, (short) 0, out, (short) 0, (short) 4);

                    cipher.init(mgmt_key, Cipher.MODE_ENCRYPT);
                    cipher.doFinal(buf, (short) (offset + 0x0E), (short) 8, out, (short) 4);
                    io.sendBuffer(out, (short) 12, apdu);
                }
            } else {
                authenticated[0] = false;
                mgmt_counter.check(new byte[]{0x01, 0x01, 0x01, 0x01}, (short) 0, (byte) 4);
                ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING
                        | mgmt_counter.getTriesRemaining()));
            }
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private void doPrivateKeyOperation(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = apdu.setIncomingAndReceive();
        short offset = apdu.getOffsetCdata();
        short id = keyMapping(p2);

        if (keys[id] == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (keys[id].getType() == KeyBuilder.TYPE_RSA_CRT_PRIVATE
                || keys[id].getType() == KeyBuilder.TYPE_RSA_PRIVATE) {
            // Add checks
        }

        if ((cla != 0x0) && (cla != 0x10)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (cla == 0x10) {
            io.receiveBuffer(buf, offset, lc);
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        if (io.isLoaded()) {
            buf = io.retrieveBuffer(buf, offset, lc);
            offset = 0;
            lc = (short) buf.length;
        }

        short cur = offset;
        if (buf[cur++] != (byte) 0x7C) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        cur += lengthLength(BERTLV.decodeLength(buf, cur));
        short m = getTag(buf, cur, lc, (byte) 0x81);
        if (m < lc && buf[m] == (byte) 0x81) {
            short k = BERTLV.decodeLength(buf, (short) (m + 1));
            m += lengthLength(k) + 1;

            byte[] signature = null;
            short l = 0;
            if (keys[id].getType() == KeyBuilder.TYPE_RSA_CRT_PRIVATE) {
                if (k != 256) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                l = (short) 264; // (256 + LL(256) + 1) + LL(260) + 1
                signature = new byte[l];
                Util.arrayCopy(new byte[]{
                    (byte) 0x7C, (byte) 0x82, (byte) 0x01, (byte) 0x04,
                    (byte) 0x82, (byte) 0x82, (byte) 0x01, (byte) 0x00
                }, (short) 0, signature, (short) 0, (short) 8);
                rsa_cipher.init(keys[id], Cipher.MODE_DECRYPT);
                try {
                    k = rsa_cipher.doFinal(buf, m, k, signature, (short) 8);
                } catch (CryptoException e) {
                    if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    }
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                if (k != 256) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            } else if (keys[id].getType() == KeyBuilder.TYPE_EC_FP_PRIVATE) {
                if (ec_signature == null) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
                signature = new byte[76];
                ec_signature.init(keys[id], Signature.MODE_SIGN);
                try {
                    k = ec_signature.sign(buf, m, k, signature, (short) 4);
                } catch (CryptoException e) {
                    if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    }
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
                if (k < 70) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                signature[0] = (byte) 0x7C;
                signature[1] = (byte) ((k + 2) & 0xFF);
                signature[2] = (byte) 0x82;
                signature[3] = (byte) (k & 0xFF);
                l = (short) (k + 4);
            }
            io.sendBuffer(signature, l, apdu);
        }
    }
}
