package org.opensearch.security.cedarling.audit;

import java.time.Instant;
import java.util.Map;

/**
 * Container for audit metrics and analytics data
 * 
 * Provides comprehensive statistics about authorization decisions,
 * performance metrics, and security patterns.
 */
public class AuditMetrics {
    
    private final long totalRequests;
    private final long allowedRequests;
    private final long deniedRequests;
    private final long errorRequests;
    private final Map<String, Long> actionMetrics;
    private final Map<String, Long> tenantMetrics;
    private final Map<String, Long> userMetrics;
    private final Instant timestamp;
    
    public AuditMetrics(
            long totalRequests,
            long allowedRequests,
            long deniedRequests,
            long errorRequests,
            Map<String, Long> actionMetrics,
            Map<String, Long> tenantMetrics,
            Map<String, Long> userMetrics
    ) {
        this.totalRequests = totalRequests;
        this.allowedRequests = allowedRequests;
        this.deniedRequests = deniedRequests;
        this.errorRequests = errorRequests;
        this.actionMetrics = actionMetrics;
        this.tenantMetrics = tenantMetrics;
        this.userMetrics = userMetrics;
        this.timestamp = Instant.now();
    }
    
    // Getters
    public long getTotalRequests() { return totalRequests; }
    public long getAllowedRequests() { return allowedRequests; }
    public long getDeniedRequests() { return deniedRequests; }
    public long getErrorRequests() { return errorRequests; }
    public Map<String, Long> getActionMetrics() { return actionMetrics; }
    public Map<String, Long> getTenantMetrics() { return tenantMetrics; }
    public Map<String, Long> getUserMetrics() { return userMetrics; }
    public Instant getTimestamp() { return timestamp; }
    
    /**
     * Calculate allow rate as percentage
     */
    public double getAllowRate() {
        if (totalRequests == 0) return 0.0;
        return (double) allowedRequests / totalRequests;
    }
    
    /**
     * Calculate deny rate as percentage
     */
    public double getDenyRate() {
        if (totalRequests == 0) return 0.0;
        return (double) deniedRequests / totalRequests;
    }
    
    /**
     * Calculate error rate as percentage
     */
    public double getErrorRate() {
        if (totalRequests == 0) return 0.0;
        return (double) errorRequests / totalRequests;
    }
    
    /**
     * Get the most frequently used action
     */
    public String getTopAction() {
        return actionMetrics.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("none");
    }
    
    /**
     * Get the most active tenant
     */
    public String getTopTenant() {
        return tenantMetrics.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("none");
    }
    
    /**
     * Get the most active user
     */
    public String getTopUser() {
        return userMetrics.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("none");
    }
    
    /**
     * Check if error rate is above threshold (indicating potential issues)
     */
    public boolean isErrorRateHigh(double threshold) {
        return getErrorRate() > threshold;
    }
    
    /**
     * Check if deny rate is above threshold (indicating potential security issues)
     */
    public boolean isDenyRateHigh(double threshold) {
        return getDenyRate() > threshold;
    }
    
    /**
     * Generate a summary string for logging
     */
    public String getSummary() {
        return String.format(
            "Total: %d, Allowed: %d (%.1f%%), Denied: %d (%.1f%%), Errors: %d (%.1f%%), Top Action: %s, Top Tenant: %s",
            totalRequests,
            allowedRequests, getAllowRate() * 100,
            deniedRequests, getDenyRate() * 100,
            errorRequests, getErrorRate() * 100,
            getTopAction(),
            getTopTenant()
        );
    }
    
    @Override
    public String toString() {
        return "AuditMetrics{" +
                "totalRequests=" + totalRequests +
                ", allowedRequests=" + allowedRequests +
                ", deniedRequests=" + deniedRequests +
                ", errorRequests=" + errorRequests +
                ", allowRate=" + String.format("%.2f", getAllowRate()) +
                ", denyRate=" + String.format("%.2f", getDenyRate()) +
                ", errorRate=" + String.format("%.2f", getErrorRate()) +
                ", timestamp=" + timestamp +
                '}';
    }
}