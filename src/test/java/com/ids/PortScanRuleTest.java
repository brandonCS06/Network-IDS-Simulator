package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.List;

public class PortScanRuleTest {

    private PortScanRule rule;
    private static final int PORT_THRESHOLD = 10;
    private static final long WINDOW_MS = 60_000;

    @Before
    public void setUp() {
        rule = new PortScanRule();
    }

    @Test
    public void testRuleCreation() {
        assertNotNull(rule);
        assertEquals("PortScanRule", rule.getName());
    }

    @Test
    public void testNullEvent() {
        List<Alert> alerts = rule.onEvent(null);
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testEventWithoutDestinationPort() {
        Event event = new Event(1000, "192.168.1.1", "alice", "PORT_CHECK", "web", new HashMap<>());
        List<Alert> alerts = rule.onEvent(event);
        
        assertTrue("Event without destination port should be ignored", alerts.isEmpty());
    }

    @Test
    public void testBelowPortThresholdNoAlert() {
        // Add events with different ports (below threshold)
        for (int i = 0; i < PORT_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 8000 + i);
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            List<Alert> alerts = rule.onEvent(event);
            
            assertTrue("Alert should not trigger below threshold", alerts.isEmpty());
        }
    }

    @Test
    public void testPortScanDetection() {
        // Add events with enough unique ports to trigger alert
        for (int i = 0; i < PORT_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 1024 + i);
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            List<Alert> alerts = rule.onEvent(event);
            
            if (i < PORT_THRESHOLD - 1) {
                assertTrue("Alert should not trigger until threshold", alerts.isEmpty());
            } else {
                assertFalse("Alert should trigger at threshold", alerts.isEmpty());
                assertEquals(1, alerts.size());
                Alert alert = alerts.get(0);
                assertEquals("PortScanRule", alert.getRule_name());
                assertEquals("high", alert.getSeverity());
                assertEquals("192.168.1.1", alert.getSource_ip());
                assertNotNull(alert.getDescription());
                assertTrue(alert.getDescription().contains("unique destination ports"));
                assertNotNull(alert.getRecommendation());
                assertNotNull(alert.getMetrics());
                assertEquals(Integer.valueOf(PORT_THRESHOLD), alert.getMetrics().get("unique_destination_ports"));
                assertEquals(Integer.valueOf(PORT_THRESHOLD), alert.getMetrics().get("threshold"));
            }
        }
    }

    @Test
    public void testSamePortMultipleTimes() {
        // Add same port multiple times from same IP (should not trigger)
        HashMap<String, Object> metadata = new HashMap<>();
        metadata.put("destination_port", 8080);
        
        for (int i = 0; i < PORT_THRESHOLD; i++) {
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            List<Alert> alerts = rule.onEvent(event);
            
            assertTrue("Same port multiple times should not trigger alert", alerts.isEmpty());
        }
    }

    @Test
    public void testMultipleSourceIPs() {
        // Add ports from IP 1 below threshold
        for (int i = 0; i < PORT_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 1024 + i);
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            rule.onEvent(event);
        }
        
        // Add ports from IP 2 below threshold (should not trigger)
        for (int i = 0; i < PORT_THRESHOLD - 1; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 2024 + i);
            Event event = new Event(2000 + (i * 100), "192.168.1.2", "bob", "PROBE", "web", metadata);
            List<Alert> alerts = rule.onEvent(event);
            
            assertTrue("IP 2 should not trigger alert yet", alerts.isEmpty());
        }
    }

    @Test
    public void testWindowExpiration() {
        // Add enough unique ports within window to trigger
        for (int i = 0; i < PORT_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 1024 + i);
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            rule.onEvent(event);
        }
        
        // Add event well beyond window (should clear old events)
        HashMap<String, Object> metadata = new HashMap<>();
        metadata.put("destination_port", 5000);
        Event expiredEvent = new Event(1000 + WINDOW_MS + 1000, "192.168.1.1", "alice", "PROBE", "web", metadata);
        List<Alert> alerts = rule.onEvent(expiredEvent);
        
        // Only 1 port in new window, below threshold
        assertTrue("Expired events should be removed from window", alerts.isEmpty());
    }

    @Test
    public void testStringPortValue() {
        // Add events with string port values
        for (int i = 0; i < PORT_THRESHOLD; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", String.valueOf(1024 + i));
            Event event = new Event(1000 + (i * 100), "192.168.1.1", "alice", "PROBE", "web", metadata);
            List<Alert> alerts = rule.onEvent(event);
            
            if (i == PORT_THRESHOLD - 1) {
                assertFalse("Alert should trigger with string ports", alerts.isEmpty());
            }
        }
    }
}
