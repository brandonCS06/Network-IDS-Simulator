package com.ids;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.io.File;

public class IDSCore {
   private List<Event> events;
    private RuleEngine ruleEngine;
    private AlertManager alertManager;

    public IDSCore()
    {
        this(RuleConfig.defaults());
    }

    public IDSCore(RuleConfig ruleConfig)
    {
        this.ruleEngine = new RuleEngine();
        this.alertManager = new AlertManager(null);

        registerDefaultRules(ruleConfig);
    }

    public void registerDefaultRules()
    {
        registerDefaultRules(RuleConfig.defaults());
    }

    public void registerDefaultRules(RuleConfig ruleConfig)
    {
        if (ruleConfig == null) {
            ruleConfig = RuleConfig.defaults();
        }
        ruleConfig.validate();

        //adds brute-force detection
        ruleEngine.registerRule(new BruteForceRule(
            ruleConfig.brute_force.window_ms,
            ruleConfig.brute_force.threshold
        ));
        //adds port scan detection
        ruleEngine.registerRule(new PortScanRule(
            ruleConfig.port_scan.window_ms,
            ruleConfig.port_scan.port_threshold
        ));
        //adds suspicious DNS detection
        ruleEngine.registerRule(new SuspiciousDnsRule(
            ruleConfig.suspicious_dns.window_ms,
            ruleConfig.suspicious_dns.minimum_dns_events,
            ruleConfig.suspicious_dns.score_threshold
        ));
        //adds SYN flood detection
        ruleEngine.registerRule(new SynFloodRule(
            ruleConfig.syn_flood.window_ms,
            ruleConfig.syn_flood.syn_threshold,
            ruleConfig.syn_flood.minimum_syn_for_ratio,
            ruleConfig.syn_flood.max_ack_ratio
        ));
        //adds ICMP sweep detection
        ruleEngine.registerRule(new IcmpSweepRule(
            ruleConfig.icmp_sweep.window_ms,
            ruleConfig.icmp_sweep.icmp_threshold
        ));
    }

    public void loadEvents(String filePath) throws IOException {
        File file = resolveEventsFile(filePath);
        if (!file.exists()) {
            throw new IOException(buildMissingEventsMessage(filePath));
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder jsonBuilder = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                jsonBuilder.append(line);
            }
            
            String json = jsonBuilder.toString();
            this.events = Event.fromJsonArray(json);
            System.out.println("Loaded " + this.events.size() + " events from " + filePath);
        }   catch (IOException e) {
            System.err.println("Error loading events: " + e.getMessage());
            throw e;
        }
    }

    private File resolveEventsFile(String filePath) {
        File requested = new File(filePath);
        if (requested.exists() || requested.isAbsolute()) {
            return requested;
        }

        File moduleRootFile = new File("IDS-simulator", filePath);
        if (moduleRootFile.exists()) {
            return moduleRootFile;
        }

        return requested;
    }

    private String buildMissingEventsMessage(String filePath) {
        File requested = new File(filePath);
        StringBuilder message = new StringBuilder();
        message.append("Events file not found: ").append(filePath).append("\n");
        message.append("Looked in: ").append(requested.getAbsolutePath());

        if (!requested.isAbsolute()) {
            File moduleRootFile = new File("IDS-simulator", filePath);
            message.append("\nAlso tried: ").append(moduleRootFile.getAbsolutePath());
        }

        message.append("\nGenerate one from the project root with: python python/log_generator.py --output Events.json");
        message.append("\nOr from the parent workspace with: python IDS-simulator/python/log_generator.py --output IDS-simulator/Events.json");
        return message.toString();
    }

    public void processEvents() {
        
        if (this.events == null || this.events.isEmpty()) {
            System.err.println("No events loaded. Call loadEvents() first.");
            return;
        }
        
        List<Alert> newAlerts = this.ruleEngine.processEvent(this.events);
        this.alertManager.addAlerts(newAlerts);
        System.out.println("Processed events and generated " + newAlerts.size() + " alerts.");
    }

    public void printAlerts()
    {
        this.alertManager.printAlerts();
    }

    public void exportAlerts(String filePath)
    {
        this.alertManager.exportToJson(filePath);
        System.out.println("Exported alerts to " + filePath);
    }

    private static String defaultAlertsPath() {
        File moduleRoot = new File("IDS-simulator");
        if (moduleRoot.isDirectory()) {
            return new File(moduleRoot, "Alerts.json").getPath();
        }

        return "Alerts.json";
    }

    public List<Alert> getAlerts(){
        return this.alertManager.getAlerts();
    }

    public void clearAlerts(){
        this.alertManager.clearAlerts();
    }

    public static void main(String[] args) {
        try {
            String eventsFile = args.length > 0 ? args[0] : "Events.json";
            RuleConfig ruleConfig = args.length > 1 ? RuleConfig.load(args[1]) : RuleConfig.defaults();
            if (args.length > 1) {
                System.out.println("Loaded rule config from " + args[1]);
            }

            IDSCore core = new IDSCore(ruleConfig);
            core.loadEvents(eventsFile);
            core.processEvents();
            core.exportAlerts(defaultAlertsPath());
            //Export to file
        } catch (IOException e) {
            System.err.println("Failed to run IDS Core: " + e.getMessage());
            System.exit(1);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid rule config: " + e.getMessage());
            System.exit(1);
        }
    }
}

   

