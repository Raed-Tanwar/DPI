package com.dpi.engine;

import com.dpi.pcap.RawPacket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * LoadBalancerThread distributes incoming packets across multiple worker threads
 * using 5-tuple hash-based load balancing to guarantee flow affinity.
 */
public class LoadBalancerThread implements Runnable {
    private final BlockingQueue<PacketJob> inputQueue;
    private final BlockingQueue<PacketJob>[] workerQueues;
    private final int numWorkers;
    private final AtomicLong dispatchedCount;

    public LoadBalancerThread(BlockingQueue<PacketJob> inputQueue,
                               BlockingQueue<PacketJob>[] workerQueues,
                               int numWorkers,
                               AtomicLong dispatchedCount) {
        this.inputQueue = inputQueue;
        this.workerQueues = workerQueues;
        this.numWorkers = numWorkers;
        this.dispatchedCount = dispatchedCount;
    }

    @Override
    public void run() {
        try {
            while (true) {
                PacketJob job = inputQueue.take();

                // Check for sentinel value (empty packet data array)
                if (job.rawPacket != null && job.rawPacket.data != null && job.rawPacket.data.length == 0) {
                    for (BlockingQueue<PacketJob> queue : workerQueues) {
                        RawPacket sentinelPkt = new RawPacket();
                        sentinelPkt.data = new byte[0];
                        queue.put(new PacketJob(sentinelPkt, null, null));
                    }
                    break;
                }

                // Hash-based worker selection for flow affinity (Task 4)
                int workerIndex = 0;
                if (job.tuple != null) {
                    workerIndex = Math.floorMod(job.tuple.hashCode(), numWorkers);
                }
                workerQueues[workerIndex].put(job);
                if (dispatchedCount != null) {
                    dispatchedCount.incrementAndGet();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("LoadBalancerThread interrupted");
        }
    }
}
