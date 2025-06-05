package org.opensearch.security.cedarling.model;

/**
 * Policy store status information from Cedarling
 */
public class PolicyStoreStatus {
    
    private final boolean active;
    private final String message;
    private final int policyCount;
    private final String lastUpdated;
    
    public PolicyStoreStatus(boolean active, String message, int policyCount, String lastUpdated) {
        this.active = active;
        this.message = message;
        this.policyCount = policyCount;
        this.lastUpdated = lastUpdated;
    }
    
    public boolean isActive() {
        return active;
    }
    
    public String getMessage() {
        return message;
    }
    
    public int getPolicyCount() {
        return policyCount;
    }
    
    public String getLastUpdated() {
        return lastUpdated;
    }
    
    @Override
    public String toString() {
        return String.format("PolicyStoreStatus{active=%s, policyCount=%d, lastUpdated='%s'}", 
                           active, policyCount, lastUpdated);
    }
}