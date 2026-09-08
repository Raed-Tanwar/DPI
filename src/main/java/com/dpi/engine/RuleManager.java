package com.dpi.engine;

import com.dpi.types.*;
import java.util.*;

public class RuleManager {
    private Set<Long> blockedIPs;
    private Set<AppType> blockedApps;
    private Set<String> blockedDomains;

    public RuleManager() {
        this.blockedIPs = new HashSet<>();
        this.blockedApps = new HashSet<>();
        this.blockedDomains = new HashSet<>();
    }

    public void addRule(String ruleType, String value) {
        switch (ruleType.toLowerCase()) {
            case "ip":
                blockedIPs.add(IpUtil.toLong(value));
                System.out.println("[Rules] Blocked IP: " + value);
                break;
            case "app":
                try {
                    blockedApps.add(AppType.valueOf(value.toUpperCase()));
                    System.out.println("[Rules] Blocked app: " + value);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Unknown app '" + value + "'", e);
                }
                break;
            case "domain":
                blockedDomains.add(value.toLowerCase());
                System.out.println("[Rules] Blocked domain: " + value);
                break;
            default:
                throw new IllegalArgumentException("Unknown rule type '" + ruleType + "'");
        }
    }

    public boolean isBlocked(long srcIp, AppType appType, String sni) {
        if (blockedIPs.contains(srcIp)) return true;
        if (blockedApps.contains(appType)) return true;
        String lowerSni = sni != null ? sni.toLowerCase() : "";
        for (String domain : blockedDomains) {
            if (lowerSni.contains(domain)) return true;
        }
        return false;
    }
}