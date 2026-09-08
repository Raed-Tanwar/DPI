package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter implements AutoCloseable {
    private final OutputStream out;
    private final String filename;
    private boolean closed = false;

    public PcapWriter(String filename, PcapReader.GlobalHeader globalHeader) throws IOException {
        this.filename = filename;
        this.out = new BufferedOutputStream(new FileOutputStream(filename));
        writeGlobalHeader(globalHeader);
    }

    private void writeGlobalHeader(PcapReader.GlobalHeader gh) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24);
        bb.order(ByteOrder.LITTLE_ENDIAN);

        long magic = (gh != null && gh.magicNumber != 0) ? gh.magicNumber : 0xa1b2c3d4L;
        int vMaj = gh != null ? gh.versionMajor : 2;
        int vMin = gh != null ? gh.versionMinor : 4;
        int thisZone = gh != null ? (int) gh.thisZone : 0;
        int sigFigs = gh != null ? (int) gh.sigFigs : 0;
        int snapLen = gh != null ? (int) gh.snapLen : 65535;
        int network = gh != null ? (int) gh.network : 1;

        bb.putInt((int) (magic & 0xFFFFFFFFL));
        bb.putShort((short) (vMaj & 0xFFFF));
        bb.putShort((short) (vMin & 0xFFFF));
        bb.putInt(thisZone);
        bb.putInt(sigFigs);
        bb.putInt(snapLen);
        bb.putInt(network);

        out.write(bb.array());
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        if (closed) return;

        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.order(ByteOrder.LITTLE_ENDIAN);

        bb.putInt((int) (packet.header.tsSec & 0xFFFFFFFFL));
        bb.putInt((int) (packet.header.tsUsec & 0xFFFFFFFFL));
        bb.putInt(packet.data.length);
        bb.putInt(packet.data.length);

        out.write(bb.array());
        out.write(packet.data);
    }

    @Override
    public synchronized void close() throws IOException {
        if (!closed) {
            closed = true;
            out.flush();
            out.close();
            System.out.println("\nOutput written to: " + filename);
        }
    }
}
