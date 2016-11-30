package org.cryptonit;

public class FileIndex {

    /**
     * X.509 Certificate for Card Authentication       (Key Reference '9E')  0x0500 '5FC101' 1905
     * Discovery Object                                                      0x6050 '7E'     19
     * X.509 Certificate for PIV Authentication        (Key Reference '9A')  0x0101 '5FC105' 1905
     * X.509 Certificate for Digital Signature         (Key Reference '9C')  0x0100 '5FC10A' 1905
     * X.509 Certificate for Key Management            (Key Reference '9D')  0x0102 '5FC10B' 1905
     */
    public final static byte DISCOVERY           = 0x3;
    public IndexEntry [] entries;

    public final static byte[] discovery = {
        /* (0x7E) Discovery Object: interindustry ISO7816 template */
        (byte) 0x7E, (byte) 0x12,
        /* - (0x4F) AID of Application */
        (byte) 0x4F, (byte) 0x0B,
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00,
        (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00,
        /* - (0x5F2F)  Usage Policy */
        (byte) 0x5F, (byte) 0x2F, (byte) 0x02, (byte) 0x40, (byte) 0x00
    };

    public FileIndex() {
        entries = new IndexEntry[11];
        entries[DISCOVERY      ] = new IndexEntry(DISCOVERY      , (short) 0x6050, discovery);
    }
}
