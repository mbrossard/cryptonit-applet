package org.cryptonit;

public class FileIndex {

    /**
     * Discovery Object                                                      0x6050 '7E'     19
     */
    public final static byte DISCOVERY           = 0x3;
    public IndexEntry [] entries;

    public final static byte[] discovery = {
        (byte) 0x7E, (byte) 0x12, (byte) 0x4F, (byte) 0x0B, (byte) 0xA0,
        (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00,
        (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00,
        (byte) 0x5F, (byte) 0x2F, (byte) 0x02, (byte) 0x40, (byte) 0x00
    };

    public FileIndex() {
        entries = new IndexEntry[4];
        entries[DISCOVERY      ] = new IndexEntry(DISCOVERY      , (short) 0x6050, discovery);
    }
}
