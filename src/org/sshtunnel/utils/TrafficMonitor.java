package org.sshtunnel.utils;

import java.util.concurrent.atomic.AtomicLong;

public class TrafficMonitor {
    private static final AtomicLong tx = new AtomicLong(0);
    private static final AtomicLong rx = new AtomicLong(0);

    public static void updateTraffic(long upload, long download) {
        if (upload > 0) {
            tx.addAndGet(upload);
        }
        if (download > 0) {
            rx.addAndGet(download);
        }
    }

    public static long getTx() {
        return tx.get();
    }

    public static long getRx() {
        return rx.get();
    }

    public static void reset() {
        tx.set(0);
        rx.set(0);
    }
}
