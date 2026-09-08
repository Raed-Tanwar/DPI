package com.dpi.engine;

import com.dpi.pcap.RawPacket;
import com.dpi.parser.ParsedPacket;
import com.dpi.types.FiveTuple;

public class PacketJob {
    public final RawPacket rawPacket;
    public final ParsedPacket parsedPacket;
    public final FiveTuple tuple;

    public PacketJob(RawPacket rawPacket, ParsedPacket parsedPacket, FiveTuple tuple) {
        this.rawPacket = rawPacket;
        this.parsedPacket = parsedPacket;
        this.tuple = tuple;
    }
}
