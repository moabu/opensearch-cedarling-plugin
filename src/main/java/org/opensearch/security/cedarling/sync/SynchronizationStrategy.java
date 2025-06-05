package org.opensearch.security.cedarling.sync;

/**
 * Enumeration of synchronization strategies for policy store updates
 * 
 * Different strategies optimize for various enterprise requirements:
 * - Performance vs consistency trade-offs
 * - Network bandwidth optimization
 * - Conflict resolution approaches
 */
public enum SynchronizationStrategy {
    
    /**
     * Full synchronization - Downloads complete policy store on every sync
     * Pros: Guarantees consistency, simple conflict resolution
     * Cons: Higher bandwidth usage, slower for large policy stores
     */
    FULL_SYNC("full", "Complete policy store download on every sync"),
    
    /**
     * Incremental synchronization - Only downloads changed policies
     * Pros: Lower bandwidth, faster sync for large stores
     * Cons: More complex conflict resolution, requires delta tracking
     */
    INCREMENTAL_SYNC("incremental", "Download only changed policies since last sync"),
    
    /**
     * Smart synchronization - Adaptive strategy based on change volume
     * Pros: Optimal bandwidth usage, automatic strategy selection
     * Cons: More complex implementation, requires change analytics
     */
    SMART_SYNC("smart", "Adaptive strategy based on detected change patterns"),
    
    /**
     * Event-driven synchronization - Real-time updates via webhooks/events
     * Pros: Near real-time updates, minimal polling overhead
     * Cons: Requires webhook infrastructure, network reliability dependency
     */
    EVENT_DRIVEN("event", "Real-time synchronization via event notifications"),
    
    /**
     * Hybrid synchronization - Combines event-driven with periodic full sync
     * Pros: Real-time updates with consistency guarantees
     * Cons: Most complex implementation, higher resource usage
     */
    HYBRID("hybrid", "Event-driven updates with periodic full synchronization");
    
    private final String code;
    private final String description;
    
    SynchronizationStrategy(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }
    
    /**
     * Parse strategy from configuration string
     */
    public static SynchronizationStrategy fromString(String strategy) {
        for (SynchronizationStrategy s : values()) {
            if (s.code.equalsIgnoreCase(strategy) || s.name().equalsIgnoreCase(strategy)) {
                return s;
            }
        }
        return FULL_SYNC; // Default fallback
    }
    
    /**
     * Check if strategy supports incremental updates
     */
    public boolean supportsIncremental() {
        return this == INCREMENTAL_SYNC || this == SMART_SYNC || this == HYBRID;
    }
    
    /**
     * Check if strategy supports real-time updates
     */
    public boolean supportsRealTime() {
        return this == EVENT_DRIVEN || this == HYBRID;
    }
    
    /**
     * Get recommended strategy based on policy store characteristics
     */
    public static SynchronizationStrategy recommendStrategy(int policyCount, double changeFrequency) {
        // Small policy stores (< 100 policies) - use full sync for simplicity
        if (policyCount < 100) {
            return FULL_SYNC;
        }
        
        // Large policy stores with low change frequency - use incremental
        if (policyCount > 1000 && changeFrequency < 0.1) {
            return INCREMENTAL_SYNC;
        }
        
        // High change frequency - consider event-driven
        if (changeFrequency > 0.5) {
            return EVENT_DRIVEN;
        }
        
        // Default to smart sync for adaptive behavior
        return SMART_SYNC;
    }
}