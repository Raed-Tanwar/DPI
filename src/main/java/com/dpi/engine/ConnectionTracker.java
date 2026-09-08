package com.dpi.engine;

import com.dpi.types.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class ConnectionTracker {
    private final Map<FiveTuple, Connection> connections;
    private final int maxConnections;

    public ConnectionTracker(int maxConnections) {
        this.connections = new HashMap<>();
        this.maxConnections = maxConnections;
    }

    public ConnectionTracker() {
        this(10000);
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        return conn;
    }

    public void cleanupStale(long timeoutSeconds) {
        Instant now = Instant.now();
        Iterator<Map.Entry<FiveTuple, Connection>> iterator = connections.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = iterator.next();
            Connection conn = entry.getValue();
            long age = Duration.between(conn.getLastSeen(), now).getSeconds();
            if (age > timeoutSeconds || conn.getState() == ConnectionState.CLOSED) {
                iterator.remove();
            }
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldestKey = null;
        Instant oldestTime = null;

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            Instant lastSeen = entry.getValue().getLastSeen();
            if (oldestTime == null || lastSeen.isBefore(oldestTime)) {
                oldestTime = lastSeen;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    public Map<FiveTuple, Connection> getConnections() {
        return connections;
    }
}
