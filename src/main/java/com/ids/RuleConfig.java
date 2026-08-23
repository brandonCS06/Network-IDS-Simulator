package com.ids;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Configurable thresholds for the built-in IDS rules.
 *
 * Fields intentionally use snake_case so the JSON config is easy to read and
 * matches the event schema style used elsewhere in the project.
 */
public class RuleConfig {
    private static final Gson gson = new GsonBuilder().create();

    public BruteForceConfig brute_force = new BruteForceConfig();
    public PortScanConfig port_scan = new PortScanConfig();
    public SuspiciousDnsConfig suspicious_dns = new SuspiciousDnsConfig();
    public SynFloodConfig syn_flood = new SynFloodConfig();
    public IcmpSweepConfig icmp_sweep = new IcmpSweepConfig();

    public static RuleConfig defaults() {
        return new RuleConfig();
    }

    public static RuleConfig load(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("Rule config file not found: " + filePath);
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            RuleConfig config = gson.fromJson(reader, RuleConfig.class);
            if (config == null) {
                throw new IllegalArgumentException("Rule config must contain a JSON object");
            }
            config.applyDefaults();
            config.validate();
            return config;
        }
    }

    private void applyDefaults() {
        if (brute_force == null) {
            brute_force = new BruteForceConfig();
        }
        if (port_scan == null) {
            port_scan = new PortScanConfig();
        }
        if (suspicious_dns == null) {
            suspicious_dns = new SuspiciousDnsConfig();
        }
        if (syn_flood == null) {
            syn_flood = new SynFloodConfig();
        }
        if (icmp_sweep == null) {
            icmp_sweep = new IcmpSweepConfig();
        }
    }

    public void validate() {
        applyDefaults();
        requirePositive(brute_force.window_ms, "brute_force.window_ms");
        requirePositive(brute_force.threshold, "brute_force.threshold");
        requirePositive(port_scan.window_ms, "port_scan.window_ms");
        requirePositive(port_scan.port_threshold, "port_scan.port_threshold");
        requirePositive(suspicious_dns.window_ms, "suspicious_dns.window_ms");
        requirePositive(suspicious_dns.minimum_dns_events, "suspicious_dns.minimum_dns_events");
        requirePositive(suspicious_dns.score_threshold, "suspicious_dns.score_threshold");
        requirePositive(syn_flood.window_ms, "syn_flood.window_ms");
        requirePositive(syn_flood.syn_threshold, "syn_flood.syn_threshold");
        requirePositive(syn_flood.minimum_syn_for_ratio, "syn_flood.minimum_syn_for_ratio");
        requirePositive(syn_flood.max_ack_ratio, "syn_flood.max_ack_ratio");
        requirePositive(icmp_sweep.window_ms, "icmp_sweep.window_ms");
        requirePositive(icmp_sweep.icmp_threshold, "icmp_sweep.icmp_threshold");
    }

    private static void requirePositive(long value, String fieldName) {
        if (value <= 0) {
            throw new IllegalArgumentException(fieldName + " must be positive");
        }
    }

    private static void requirePositive(int value, String fieldName) {
        if (value <= 0) {
            throw new IllegalArgumentException(fieldName + " must be positive");
        }
    }

    private static void requirePositive(double value, String fieldName) {
        if (value <= 0.0d) {
            throw new IllegalArgumentException(fieldName + " must be positive");
        }
    }

    public static class BruteForceConfig {
        public long window_ms = 60_000L;
        public int threshold = 5;
    }

    public static class PortScanConfig {
        public long window_ms = 60_000L;
        public int port_threshold = 30;
    }

    public static class SuspiciousDnsConfig {
        public long window_ms = 60_000L;
        public int minimum_dns_events = 5;
        public int score_threshold = 8;
    }

    public static class SynFloodConfig {
        public long window_ms = 10_000L;
        public int syn_threshold = 60;
        public int minimum_syn_for_ratio = 30;
        public double max_ack_ratio = 0.20d;
    }

    public static class IcmpSweepConfig {
        public long window_ms = 60_000L;
        public int icmp_threshold = 30;
    }
}
