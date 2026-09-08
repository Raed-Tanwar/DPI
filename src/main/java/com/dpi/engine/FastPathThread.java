package com.dpi.engine;

import com.dpi.pcap.RawPacket;
import com.dpi.pcap.PcapWriter;
import com.dpi.parser.*;
import com.dpi.extractor.*;
import com.dpi.types.*;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

/**
 * FastPathThread processes packets assigned by the load balancer.
 * Each worker thread has its own worker-local flow table to eliminate data races.
 */
public class FastPathThread implements Runnable {
    private final int threadId;
    private final BlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connectionTracker;
    private final RuleManager ruleManager;
    private final DPIStats stats;
    private final PcapWriter pcapWriter;
    private final CountDownLatch completionLatch;
    private final AtomicLong processedCount;

    public FastPathThread(int threadId,
                          BlockingQueue<PacketJob> inputQueue,
                          RuleManager ruleManager,
                          DPIStats stats,
                          PcapWriter pcapWriter,
                          CountDownLatch completionLatch,
                          AtomicLong processedCount) {
        this.threadId = threadId;
        this.inputQueue = inputQueue;
        this.connectionTracker = new ConnectionTracker();
        this.ruleManager = ruleManager;
        this.stats = stats;
        this.pcapWriter = pcapWriter;
        this.completionLatch = completionLatch;
        this.processedCount = processedCount;
    }

    public Map<FiveTuple, Connection> getFlowTable() {
        return connectionTracker.getConnections();
    }

    @Override
    public void run() {
        try {
            while (true) {
                PacketJob job = inputQueue.take();

                if (job.rawPacket != null && job.rawPacket.data != null && job.rawPacket.data.length == 0) {
                    break;
                }

                processJob(job);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("FastPathThread " + threadId + " interrupted");
        } finally {
            completionLatch.countDown();
        }
    }

    private void processJob(PacketJob job) {
        if (processedCount != null) {
            processedCount.incrementAndGet();
        }
        RawPacket rawPacket = job.rawPacket;
        stats.incTotalPackets();
        stats.addTotalBytes(rawPacket.data.length);

        ParsedPacket parsed = job.parsedPacket;
        if (parsed == null) {
            parsed = new ParsedPacket();
            if (!PacketParser.parse(rawPacket, parsed)) {
                return;
            }
        }

        if (parsed.hasTCP) {
            stats.incTcpPackets();
        } else if (parsed.hasUDP) {
            stats.incUdpPackets();
        }

        FiveTuple tuple = job.tuple;
        if (tuple == null) {
            tuple = extractFiveTuple(parsed);
            if (tuple == null) return;
        }

        Connection connection = connectionTracker.getOrCreateConnection(tuple);

        // Connection lifecycle state tracking
        updateConnectionState(connection, parsed);

        classifyFlow(parsed, connection);

        // Sticky flow blocking (Task 2)
        if (connection.isBlocked()) {
            connection.setAction(PacketAction.DROP);
            stats.incDroppedPackets();
        } else if (ruleManager.isBlocked(tuple.getSrcIp(), connection.getAppType(), connection.getSni())) {
            connection.setBlocked(true);
            connection.setAction(PacketAction.DROP);
            stats.incDroppedPackets();

            String appStr = AppType.toDisplayString(connection.getAppType());
            String sniStr = connection.getSni();
            String detail = sniStr.isEmpty() ? appStr : (appStr + ": " + sniStr);
            System.out.println("[BLOCKED] " + parsed.srcIp + " -> " + parsed.destIp + " (" + detail + ")");
        } else {
            connection.setAction(PacketAction.FORWARD);
            stats.incForwardedPackets();
            if (pcapWriter != null) {
                try {
                    pcapWriter.writePacket(rawPacket);
                } catch (Exception e) {
                    System.err.println("Error writing to PCAP: " + e.getMessage());
                }
            }
        }

        connection.incPacketsIn();
        connection.addBytesIn(rawPacket.data.length);
        connection.updateLastSeen();
    }

    private void updateConnectionState(Connection connection, ParsedPacket parsed) {
        if (!parsed.hasTCP) return;
        byte flags = parsed.tcpFlags;
        if ((flags & PacketParser.TCPFlags.SYN) != 0) {
            connection.setSynSeen(true);
            if ((flags & PacketParser.TCPFlags.ACK) != 0) {
                connection.setSynAckSeen(true);
            }
            if (connection.getState() != ConnectionState.CLASSIFIED && !connection.isBlocked()) {
                connection.setState(ConnectionState.ESTABLISHED);
            }
        }
        if ((flags & PacketParser.TCPFlags.FIN) != 0 || (flags & PacketParser.TCPFlags.RST) != 0) {
            connection.setFinSeen(true);
            if (!connection.isBlocked()) {
                connection.setState(ConnectionState.CLOSED);
            }
        }
    }

    private FiveTuple extractFiveTuple(ParsedPacket parsed) {
        if (!parsed.hasIP) {
            return null;
        }

        long srcIp = IpUtil.toLong(parsed.srcIp);
        long dstIp = IpUtil.toLong(parsed.destIp);

        return new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
    }

    private void classifyFlow(ParsedPacket parsed, Connection connection) {
        if (connection.getState() == ConnectionState.CLASSIFIED) {
            return;
        }

        if (parsed.destPort == 443 && parsed.payloadLength > 5) {
            Optional<String> sni = SNIExtractor.extract(parsed.payloadData, 0, parsed.payloadLength);
            if (sni.isPresent()) {
                connection.setSni(sni.get());
                connection.setAppType(AppType.fromSni(sni.get()));
                connection.setState(ConnectionState.CLASSIFIED);
                return;
            }
        } else if (parsed.destPort == 80 && parsed.payloadLength > 5) {
            Optional<String> host = HTTPHostExtractor.extract(parsed.payloadData, 0, parsed.payloadLength);
            if (host.isPresent()) {
                connection.setSni(host.get());
                connection.setAppType(AppType.fromSni(host.get()));
                connection.setState(ConnectionState.CLASSIFIED);
                return;
            }
        } else if (parsed.destPort == 53 && parsed.payloadLength > 5) {
            Optional<String> domain = DNSExtractor.extractQuery(parsed.payloadData, 0, parsed.payloadLength);
            if (domain.isPresent()) {
                connection.setSni(domain.get());
                connection.setAppType(AppType.DNS);
                connection.setState(ConnectionState.CLASSIFIED);
                return;
            }
        }

        // Port-based fallback
        if (connection.getAppType() == AppType.UNKNOWN) {
            if (parsed.destPort == 443) {
                connection.setAppType(AppType.HTTPS);
            } else if (parsed.destPort == 80) {
                connection.setAppType(AppType.HTTP);
            } else if (parsed.destPort == 53) {
                connection.setAppType(AppType.DNS);
            }
        }
    }
}
