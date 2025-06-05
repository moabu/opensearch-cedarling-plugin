package org.opensearch.security.cedarling.audit;

/**
 * Enumeration of security event types for audit logging
 * 
 * Each event type includes severity level for proper alerting and monitoring
 */
public enum SecurityEventType {
    
    // Authorization events
    AUTHORIZATION_SUCCESS("INFO"),
    AUTHORIZATION_FAILURE("WARN"),
    AUTHORIZATION_ERROR("ERROR"),
    
    // Policy management events
    POLICY_SYNC_SUCCESS("INFO"),
    POLICY_SYNC_FAILURE("ERROR"),
    POLICY_UPDATE("INFO"),
    POLICY_DELETE("WARN"),
    POLICY_VALIDATION_ERROR("ERROR"),
    
    // Service connectivity events
    CEDARLING_SERVICE_UNAVAILABLE("ERROR"),
    CEDARLING_SERVICE_RECOVERED("INFO"),
    CEDARLING_TIMEOUT("WARN"),
    
    // Configuration events
    PLUGIN_STARTED("INFO"),
    PLUGIN_STOPPED("INFO"),
    CONFIGURATION_UPDATED("INFO"),
    CONFIGURATION_ERROR("ERROR"),
    
    // Security incidents
    SUSPICIOUS_ACTIVITY("ERROR"),
    REPEATED_ACCESS_DENIED("WARN"),
    UNUSUAL_PATTERN_DETECTED("WARN"),
    
    // Performance events
    HIGH_LATENCY_DETECTED("WARN"),
    CACHE_INVALIDATION("DEBUG"),
    METRICS_REPORT("INFO");
    
    private final String severity;
    
    SecurityEventType(String severity) {
        this.severity = severity;
    }
    
    public String getSeverity() {
        return severity;
    }
    
    /**
     * Check if this event type represents an error condition
     */
    public boolean isError() {
        return "ERROR".equals(severity);
    }
    
    /**
     * Check if this event type represents a warning condition
     */
    public boolean isWarning() {
        return "WARN".equals(severity);
    }
    
    /**
     * Check if this event type is informational
     */
    public boolean isInfo() {
        return "INFO".equals(severity);
    }
    
    /**
     * Get events that should trigger alerts
     */
    public static SecurityEventType[] getAlertEvents() {
        return new SecurityEventType[] {
            AUTHORIZATION_ERROR,
            POLICY_SYNC_FAILURE,
            POLICY_VALIDATION_ERROR,
            CEDARLING_SERVICE_UNAVAILABLE,
            CONFIGURATION_ERROR,
            SUSPICIOUS_ACTIVITY
        };
    }
}