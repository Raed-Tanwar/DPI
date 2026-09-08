package com.dpi.engine;

import com.dpi.pcap.*;
import com.dpi.parser.*;
import com.dpi.extractor.*;
import com.dpi.types.*;
import java.util.*;
import java.util.concurrent.*;

public class DPIEngine {
    private PcapReader pcapReader;
    private PcapWriter pcapWriter;
    private RuleManager ruleManager;
    private Map<FiveTuple, Connection> flows;
    private DPIStats stats;
    private String inputFile;
    private String outputFile;

    public DPIEngine(String inputFile, String outputFile) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
        this.pcapReader = new PcapReader();
        this.ruleManager = new RuleManager();
        this.flows = new ConcurrentHashMap<>();
        this.stats = new DPIStats();
    }

    public boolean process() {
        try {
            if (!pcapReader.open(inputFile)) {
                System.err.println("Failed to open PCAP file");
                return false;
            }

            if (outputFile != null && !outputFile.isEmpty()) {
                this.pcapWriter = new PcapWriter(outputFile, pcapReader.getGlobalHeader());
            }

            System.out.println("Starting DPI processing...");

            RawPacket rawPacket = new RawPacket();
            int packetCount = 0;

            while (pcapReader.readNextPacket(rawPacket)) {
                stats.incTotalPackets();
                stats.addTotalBytes(rawPacket.data.length);

                ParsedPacket parsed = new ParsedPacket();
                if (!PacketParser.parse(rawPacket, parsed)) {
                    continue;
                }

                FiveTuple tuple = extractFiveTuple(parsed);
                if (tuple == null) {
                    continue;
                }

                // Track protocol statistics
                if (parsed.hasTCP) {
                    stats.incTcpPackets();
                } else if (parsed.hasUDP) {
                    stats.incUdpPackets();
                }

                Connection connection = flows.computeIfAbsent(tuple, t -> new Connection(t));

                // Connection state lifecycle tracking
                updateConnectionState(connection, parsed);

                classifyFlow(parsed, connection);

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
                        pcapWriter.writePacket(rawPacket);
                    }
                }

                connection.incPacketsIn();
                connection.addBytesIn(rawPacket.data.length);

                packetCount++;
                if (packetCount % 100 == 0) {
                    System.out.println("Processed " + packetCount + " packets");
                }
            }

            pcapReader.close();
            if (pcapWriter != null) {
                pcapWriter.close();
            }

            generateReport();
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void updateConnectionState(Connection connection, ParsedPacket parsed) {
        if (!parsed.hasTCP) return;
        byte flags = parsed.tcpFlags;
        if ((flags & PacketParser.TCPFlags.SYN) != 0) {
            connection.setSynSeen(true);
            if ((flags & PacketParser.TCPFlags.ACK) != 0) {
                connection.setSynAckSeen(true);
                if (connection.getState() != ConnectionState.CLASSIFIED && !connection.isBlocked()) {
                    connection.setState(ConnectionState.ESTABLISHED);
                }
            } else {
                if (connection.getState() != ConnectionState.CLASSIFIED && !connection.isBlocked()) {
                    connection.setState(ConnectionState.ESTABLISHED);
                }
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

    private void generateReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Total Packets:                " + padValue(stats.getTotalPackets()));
        System.out.println("║ Total Bytes:                  " + padValue(stats.getTotalBytes()));
        System.out.println("║ TCP Packets:                  " + padValue(stats.getTcpPackets()));
        System.out.println("║ UDP Packets:                  " + padValue(stats.getUdpPackets()));
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Forwarded:                    " + padValue(stats.getForwardedPackets()));
        System.out.println("║ Dropped:                      " + padValue(stats.getDroppedPackets()));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        System.out.println("\n[Detected Domains/SNIs]");
        flows.values().stream()
            .filter(c -> c.getSni() != null && !c.getSni().isEmpty())
            .sorted(Comparator.comparing(Connection::getSni))
            .map(c -> String.format("  - %s -> %s", c.getSni(), AppType.toDisplayString(c.getAppType())))
            .distinct()
            .forEach(System.out::println);
    }

    private String padValue(long value) {
        return String.format("%-30d", value) + " ║";
    }

    public void addBlockRule(String type, String value) {
        ruleManager.addRule(type, value);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsageAndExit();
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine engine = new DPIEngine(inputFile, outputFile);

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            try {
                if (arg.equals("--block-app") && i + 1 < args.length) {
                    engine.addBlockRule("app", args[++i]);
                } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                    engine.addBlockRule("domain", args[++i]);
                } else if (arg.equals("--block-ip") && i + 1 < args.length) {
                    engine.addBlockRule("ip", args[++i]);
                } else {
                    System.err.println("Unknown option '" + arg + "'");
                    printUsageAndExit();
                }
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                printUsageAndExit();
            }
        }

        if (engine.process()) {
            System.out.println("DPI processing completed successfully");
        } else {
            System.out.println("DPI processing failed");
            System.exit(1);
        }
    }

    private static void printUsageAndExit() {
        System.out.println("Usage: java DPIEngine <input.pcap> <output.pcap> [--block-app APP] [--block-domain DOMAIN] [--block-ip IP]");
        System.out.println("Valid apps: YOUTUBE, FACEBOOK, GOOGLE, NETFLIX, AMAZON, MICROSOFT, APPLE, INSTAGRAM, TWITTER, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE, WHATSAPP, HTTP, HTTPS, DNS, TLS, QUIC");
        System.exit(1);
    }
}