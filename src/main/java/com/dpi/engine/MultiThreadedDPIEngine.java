package com.dpi.engine;

import com.dpi.pcap.*;
import com.dpi.parser.*;
import com.dpi.types.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class MultiThreadedDPIEngine {
    private PcapReader pcapReader;
    private PcapWriter pcapWriter;
    private RuleManager ruleManager;
    private DPIStats stats;
    private String inputFile;
    private String outputFile;
    private int numThreads;

    // Thread statistics
    private AtomicLong lbDispatchedCount = new AtomicLong(0);
    private AtomicLong[] workerProcessedCounts;

    // FastPath worker threads
    private List<FastPathThread> workerThreads;

    // Thread-safe queues
    private BlockingQueue<PacketJob> inputQueue;
    private BlockingQueue<PacketJob>[] workerQueues;
    private ExecutorService executorService;
    private CountDownLatch workerCompletionLatch;

    @SuppressWarnings("unchecked")
    public MultiThreadedDPIEngine(String inputFile, String outputFile, int numThreads) {
        this.inputFile = inputFile;
        this.outputFile = outputFile;
        this.numThreads = numThreads > 0 ? numThreads : Runtime.getRuntime().availableProcessors();
        this.pcapReader = new PcapReader();
        this.ruleManager = new RuleManager();
        this.stats = new DPIStats();
        this.workerThreads = new ArrayList<>();

        this.workerProcessedCounts = new AtomicLong[this.numThreads];
        for (int i = 0; i < this.numThreads; i++) {
            this.workerProcessedCounts[i] = new AtomicLong(0);
        }

        // Initialize queues
        this.inputQueue = new LinkedBlockingQueue<>(10000);
        this.workerQueues = new BlockingQueue[this.numThreads];
        for (int i = 0; i < this.numThreads; i++) {
            this.workerQueues[i] = new LinkedBlockingQueue<>(1000);
        }

        this.workerCompletionLatch = new CountDownLatch(this.numThreads);
        this.executorService = Executors.newFixedThreadPool(this.numThreads + 2);
    }

    public boolean process() {
        try {
            if (!pcapReader.open(inputFile)) {
                System.err.println("Failed to open PCAP file: " + inputFile);
                return false;
            }

            if (outputFile != null && !outputFile.isEmpty()) {
                this.pcapWriter = new PcapWriter(outputFile, pcapReader.getGlobalHeader());
            }

            System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║              DPI ENGINE v2.0 (Multi-threaded)                 ║");
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.println(String.format("║ Worker Threads: %-44d ║", numThreads));
            System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

            // Start load balancer thread
            executorService.submit(new LoadBalancerThread(inputQueue, workerQueues, numThreads, lbDispatchedCount));

            // Start worker threads with per-worker flow tables (Task 5)
            for (int i = 0; i < numThreads; i++) {
                FastPathThread worker = new FastPathThread(
                    i,
                    workerQueues[i],
                    ruleManager,
                    stats,
                    pcapWriter,
                    workerCompletionLatch,
                    workerProcessedCounts[i]
                );
                workerThreads.add(worker);
                executorService.submit(worker);
            }

            // Reader loop
            int packetCount = 0;
            RawPacket rawPacket = new RawPacket();

            while (pcapReader.readNextPacket(rawPacket)) {
                RawPacket cloned = new RawPacket();
                cloned.header = rawPacket.header;
                cloned.data = rawPacket.data.clone();

                ParsedPacket parsed = new ParsedPacket();
                FiveTuple tuple = null;
                if (PacketParser.parse(cloned, parsed) && parsed.hasIP) {
                    long srcIp = IpUtil.toLong(parsed.srcIp);
                    long dstIp = IpUtil.toLong(parsed.destIp);
                    tuple = new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
                }

                PacketJob job = new PacketJob(cloned, parsed, tuple);

                try {
                    inputQueue.put(job);
                    packetCount++;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            pcapReader.close();

            // Sentinel packet to signal end of input
            RawPacket sentinelPkt = new RawPacket();
            sentinelPkt.data = new byte[0];
            inputQueue.put(new PacketJob(sentinelPkt, null, null));

            // Wait for workers to finish
            boolean completed = workerCompletionLatch.await(5, TimeUnit.MINUTES);
            if (!completed) {
                System.err.println("Workers did not complete in time");
                return false;
            }

            if (pcapWriter != null) {
                pcapWriter.close();
            }

            // Shutdown executor pool
            executorService.shutdown();
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }

            generateReport();
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void generateReport() {
        // Merge worker flow tables
        Map<FiveTuple, Connection> mergedFlows = new HashMap<>();
        for (FastPathThread worker : workerThreads) {
            mergedFlows.putAll(worker.getFlowTable());
        }

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Total Packets:      " + String.format("%-10d", stats.getTotalPackets()) + "                             ║");
        System.out.println("║ Forwarded:          " + String.format("%-10d", stats.getForwardedPackets()) + "                             ║");
        System.out.println("║ Dropped:            " + String.format("%-10d", stats.getDroppedPackets()) + "                             ║");
        System.out.println("║ Active Flows:       " + String.format("%-10d", mergedFlows.size()) + "                             ║");

        // Thread Statistics
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                             ║");
        System.out.println("║   LB0 dispatched:   " + String.format("%-12d", lbDispatchedCount.get()) + "                           ║");
        for (int i = 0; i < numThreads; i++) {
            System.out.println(String.format("║   FP%-2d processed:   %-12d                           ║", i, workerProcessedCounts[i].get()));
        }

        // Application Breakdown
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        Map<AppType, Long> appCounts = new HashMap<>();
        for (Connection conn : mergedFlows.values()) {
            appCounts.put(conn.getAppType(), appCounts.getOrDefault(conn.getAppType(), 0L) + conn.getPacketsIn());
        }

        long totalPackets = stats.getTotalPackets();
        List<Map.Entry<AppType, Long>> sortedApps = appCounts.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .collect(Collectors.toList());

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            AppType app = entry.getKey();
            long count = entry.getValue();
            double pct = totalPackets > 0 ? (100.0 * count / totalPackets) : 0.0;
            int barLen = (int) (pct / 5);
            StringBuilder barStr = new StringBuilder();
            for (int b = 0; b < barLen; b++) barStr.append('#');

            System.out.println(String.format("║ %-15s%8d %5.1f%% %-20s  ║",
                AppType.toDisplayString(app), count, pct, barStr.toString()));
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // Detected Domains/SNIs
        List<Connection> sniConnections = mergedFlows.values().stream()
            .filter(c -> c.getSni() != null && !c.getSni().isEmpty())
            .sorted(Comparator.comparing(Connection::getSni))
            .collect(Collectors.toList());

        if (!sniConnections.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            Set<String> printed = new HashSet<>();
            for (Connection conn : sniConnections) {
                String line = String.format("  - %s -> %s", conn.getSni(), AppType.toDisplayString(conn.getAppType()));
                if (printed.add(line)) {
                    System.out.println(line);
                }
            }
        }
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
        int numThreads = Runtime.getRuntime().availableProcessors();
        int numLbs = 1;
        int fpsPerLb = 0;

        List<String[]> rulesToAdd = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            try {
                if (arg.equals("--threads") && i + 1 < args.length) {
                    numThreads = Integer.parseInt(args[++i]);
                } else if (arg.equals("--lbs") && i + 1 < args.length) {
                    numLbs = Integer.parseInt(args[++i]);
                } else if (arg.equals("--fps") && i + 1 < args.length) {
                    fpsPerLb = Integer.parseInt(args[++i]);
                } else if (arg.equals("--block-app") && i + 1 < args.length) {
                    rulesToAdd.add(new String[]{"app", args[++i]});
                } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                    rulesToAdd.add(new String[]{"domain", args[++i]});
                } else if (arg.equals("--block-ip") && i + 1 < args.length) {
                    rulesToAdd.add(new String[]{"ip", args[++i]});
                } else {
                    System.err.println("Unknown option '" + arg + "'");
                    printUsageAndExit();
                }
            } catch (NumberFormatException e) {
                System.err.println("Invalid numeric argument for option '" + arg + "'");
                printUsageAndExit();
            }
        }

        if (fpsPerLb > 0) {
            numThreads = numLbs * fpsPerLb;
        }

        MultiThreadedDPIEngine engine = new MultiThreadedDPIEngine(inputFile, outputFile, numThreads);

        for (String[] rule : rulesToAdd) {
            try {
                engine.addBlockRule(rule[0], rule[1]);
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
        System.out.println("Usage: java MultiThreadedDPIEngine <input.pcap> <output.pcap> [--threads N] [--lbs N] [--fps M] [--block-app APP] [--block-domain DOMAIN] [--block-ip IP]");
        System.out.println("Valid apps: YOUTUBE, FACEBOOK, GOOGLE, NETFLIX, AMAZON, MICROSOFT, APPLE, INSTAGRAM, TWITTER, TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE, WHATSAPP, HTTP, HTTPS, DNS, TLS, QUIC");
        System.exit(1);
    }
}
