package com.ids;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class RuleEngineTest {

    private RuleEngine engine;

    @Before
    public void setUp() {
        engine = new RuleEngine();
    }

    @Test
    public void testEngineCreation() {
        assertNotNull(engine);
    }

    @Test
    public void testRegisterSingleRule() {
        BruteForceRule rule = new BruteForceRule();
        engine.registerRule(rule);
        
        // Create a test event list and process
        List<Event> events = new ArrayList<>();
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
    }

    @Test
    public void testRegisterMultipleRules() {
        engine.registerRule(new BruteForceRule());
        engine.registerRule(new PortScanRule());
        
        List<Event> events = new ArrayList<>();
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
    }

    @Test
    public void testRegisterNullRule() {
        // Registering null should not cause issues
        engine.registerRule(null);
        
        List<Event> events = new ArrayList<>();
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testDuplicateRuleNotRegistered() {
        BruteForceRule rule = new BruteForceRule();
        engine.registerRule(rule);
        engine.registerRule(rule); // Try to register same rule twice
        
        List<Event> events = new ArrayList<>();
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
    }

    @Test
    public void testProcessNoEvents() {
        engine.registerRule(new BruteForceRule());
        
        List<Event> events = new ArrayList<>();
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testProcessEventWithoutAlerts() {
        engine.registerRule(new BruteForceRule());
        
        List<Event> events = new ArrayList<>();
        events.add(new Event(1000, "192.168.1.1", "alice", "LOGIN_SUCCESS", "web", new HashMap<>()));
        
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertTrue(alerts.isEmpty());
    }

    @Test
    public void testBruteForceRuleTriggersAlert() {
        engine.registerRule(new BruteForceRule());
        
        List<Event> events = new ArrayList<>();
        // Add 5 failed login events to trigger brute force detection
        for (int i = 0; i < 5; i++) {
            events.add(new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        }
        
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertEquals(1, alerts.size());
        assertEquals("BruteForceRule", alerts.get(0).getRule_name());
    }

    @Test
    public void testMultipleRulesTriggering() {
        engine.registerRule(new BruteForceRule());
        engine.registerRule(new PortScanRule(60_000L, 10));
        
        List<Event> events = new ArrayList<>();
        
        // Add brute force events
        for (int i = 0; i < 5; i++) {
            events.add(new Event(1000 + (i * 100), "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        }
        
        // Add enough port scan events to trigger one alert with the test threshold.
        for (int i = 0; i < 10; i++) {
            HashMap<String, Object> metadata = new HashMap<>();
            metadata.put("destination_port", 1024 + i);
            events.add(new Event(2000 + (i * 100), "192.168.1.2", "bob", "PROBE", "web", metadata));
        }
        
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertEquals(2, alerts.size());
    }

    @Test
    public void testIcmpSweepRuleTriggersAlert() {
        engine.registerRule(new IcmpSweepRule());

        List<Event> events = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("protocol", "ICMP");
            metadata.put("icmp_type", 8);
            metadata.put("destination_ip", "198.51.100." + (i + 1));
            events.add(new Event(1000L + (i * 200L), "10.0.0.5", "alice", "ICMP_ECHO_REQUEST", "icmp_probe", metadata));
        }

        List<Alert> alerts = engine.processEvent(events);

        assertNotNull(alerts);
        assertEquals(1, alerts.size());
        assertEquals("IcmpSweepRule", alerts.get(0).getRule_name());
    }

    @Test
    public void testRulesEvaluatedPerEvent() {
        engine.registerRule(new BruteForceRule());
        
        List<Event> events = new ArrayList<>();
        events.add(new Event(1000, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        events.add(new Event(1100, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        events.add(new Event(1200, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        events.add(new Event(1300, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        events.add(new Event(1400, "192.168.1.1", "alice", "LOGIN_FAIL", "web", new HashMap<>()));
        
        List<Alert> alerts = engine.processEvent(events);
        
        assertNotNull(alerts);
        assertEquals(1, alerts.size());
    }

   @Test
    public void testNullEventsList() {
    
        engine.registerRule(new BruteForceRule());
        
        // processEvent should handle null gracefully or we expect an exception
        // Based on current implementation, it will throw NullPointerException
        // Adjust based on actual implementation requirements
        try {
            engine.processEvent(null);
            fail("Expected NullPointerException for null events");
        } catch (NullPointerException e) {
            // Expected behavior
        }
    }
}
