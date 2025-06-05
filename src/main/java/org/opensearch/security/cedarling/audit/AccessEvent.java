package org.opensearch.security.cedarling.audit;

import java.time.Instant;

/**
 * Represents a single access event for analytics processing
 * 
 * Contains all relevant information about an authorization request
 * and response for pattern analysis and threat detection.
 */
public class AccessEvent {
    
    private final String userId;
    private final String tenant;
    private final String action;
    private final String resourceType;
    private final String resourceId;
    private final boolean allowed;
    private final long processingTime;
    private final Instant timestamp;
    
    public AccessEvent(
            String userId,
            String tenant,
            String action,
            String resourceType,
            String resourceId,
            boolean allowed,
            long processingTime,
            Instant timestamp
    ) {
        this.userId = userId;
        this.tenant = tenant;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.allowed = allowed;
        this.processingTime = processingTime;
        this.timestamp = timestamp;
    }
    
    // Getters
    public String getUserId() { return userId; }
    public String getTenant() { return tenant; }
    public String getAction() { return action; }
    public String getResourceType() { return resourceType; }
    public String getResourceId() { return resourceId; }
    public boolean isAllowed() { return allowed; }
    public long getProcessingTime() { return processingTime; }
    public Instant getTimestamp() { return timestamp; }
    
    /**
     * Check if this event represents a failed access attempt
     */
    public boolean isFailure() {
        return !allowed;
    }
    
    /**
     * Check if this event represents an administrative action
     */
    public boolean isAdministrativeAction() {
        return action != null && (
            action.toLowerCase().contains("admin") ||
            action.toLowerCase().contains("delete") ||
            action.toLowerCase().contains("create") ||
            action.toLowerCase().contains("update") ||
            action.toLowerCase().contains("manage")
        );
    }
    
    /**
     * Check if processing time indicates slow performance
     */
    public boolean isSlowPerformance(long thresholdMs) {
        return processingTime > thresholdMs;
    }
    
    /**
     * Get the hour of day for time-based analysis
     */
    public int getHourOfDay() {
        return timestamp.atZone(java.time.ZoneOffset.UTC).getHour();
    }
    
    /**
     * Get the day of week for pattern analysis
     */
    public java.time.DayOfWeek getDayOfWeek() {
        return timestamp.atZone(java.time.ZoneOffset.UTC).getDayOfWeek();
    }
    
    /**
     * Check if this event occurred recently (within specified minutes)
     */
    public boolean isRecent(long minutes) {
        return timestamp.isAfter(Instant.now().minus(minutes, java.time.temporal.ChronoUnit.MINUTES));
    }
    
    @Override
    public String toString() {
        return "AccessEvent{" +
                "userId='" + userId + '\'' +
                ", tenant='" + tenant + '\'' +
                ", action='" + action + '\'' +
                ", resourceType='" + resourceType + '\'' +
                ", resourceId='" + resourceId + '\'' +
                ", allowed=" + allowed +
                ", processingTime=" + processingTime +
                ", timestamp=" + timestamp +
                '}';
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        
        AccessEvent that = (AccessEvent) o;
        
        return allowed == that.allowed &&
               processingTime == that.processingTime &&
               userId.equals(that.userId) &&
               java.util.Objects.equals(tenant, that.tenant) &&
               action.equals(that.action) &&
               resourceType.equals(that.resourceType) &&
               resourceId.equals(that.resourceId) &&
               timestamp.equals(that.timestamp);
    }
    
    @Override
    public int hashCode() {
        return java.util.Objects.hash(userId, tenant, action, resourceType, resourceId, allowed, processingTime, timestamp);
    }
}