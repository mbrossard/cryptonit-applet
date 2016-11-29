package org.cryptonit;

public class IndexEntry {
    public byte index;
    public short container;
    public byte [] content;

    public IndexEntry(byte index, short container, byte [] content) {
        this.index = index;
        this.container = container;
        this.content = content;            
    }
}
