package com.ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PortScanRule implements RuleEngineRules {
    private static final long DEFAULT_WINDOW_MS = 60_000;
    private static final int DEFAULT_PORT_THRESHOLD = 30;
    private final Map<String, List<Event>> recentEventsByIp = new HashMap<>();
    private final long windowMs;
    private final int portThreshold;
    private final String ruleName = "PortScanRule";
    private final String severity = "high";

    public PortScanRule() {
        this(DEFAULT_WINDOW_MS, DEFAULT_PORT_THRESHOLD);
    }

    public PortScanRule(long windowMs, int portThreshold) {
        if (windowMs <= 0) {
            throw new IllegalArgumentException("windowMs must be positive");
        }
        if (portThreshold <= 0) {
            throw new IllegalArgumentException("portThreshold must be positive");
        }
        this.windowMs = windowMs;
        this.portThreshold = portThreshold;
    }

    @Override
    public List<Alert> onEvent(Event event) {
        if (event == null) {
            return Collections.emptyList();
        }

        Integer destinationPort = event.getDestinationPort();
        if (destinationPort == null) {
            return Collections.emptyList();
        }

        String sourceIp = event.getSource_ip();
        List<Event> history = recentEventsByIp.computeIfAbsent(sourceIp, key -> new ArrayList<Event>());
        history.add(event);
        pruneExpired(history, event.getTimestamp());

        Set<Integer> uniquePorts = new HashSet<Integer>();
        for (Event historyEvent : history) {
            Integer port = historyEvent.getDestinationPort();
            if (port != null) {
                uniquePorts.add(port);
            }
        }

        if (uniquePorts.size() >= portThreshold) {
            Map<String, Object> metrics = new HashMap<String, Object>();
            metrics.put("unique_destination_ports", Integer.valueOf(uniquePorts.size()));
            metrics.put("threshold", Integer.valueOf(portThreshold));
            metrics.put("window_ms", Long.valueOf(windowMs));
            metrics.put("window_seconds", Long.valueOf(windowMs / 1000));

            String description = "Source " + sourceIp + " contacted " + uniquePorts.size()
                + " unique destination ports within " + (windowMs / 1000)
                + " seconds, which matches horizontal or vertical port scan behavior.";
            String recommendation = "Check whether this source is an approved scanner; otherwise investigate the host and consider blocking repeated probes.";

            Alert alert = new Alert(
                event.getTimestamp(),
                ruleName,
                severity,
                new ArrayList<Event>(history),
                sourceIp,
                description,
                recommendation,
                metrics
            );
            return Collections.singletonList(alert);
        }

        return Collections.emptyList();
    }

    private void pruneExpired(List<Event> history, long timestamp) {
        long cutoff = timestamp - windowMs;
        while (!history.isEmpty() && history.get(0).getTimestamp() < cutoff) {
            history.remove(0);
        }
    }

    @Override
    public String getName() {
        return ruleName;
    }
}
