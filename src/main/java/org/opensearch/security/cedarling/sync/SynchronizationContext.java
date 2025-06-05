package org.opensearch.security.cedarling.sync;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Context information for policy store synchronization operations
 * 
 * Provides additional metadata and state information that conflict resolvers
 * and synchronization strategies can use to make informed decisions.
 */
public class SynchronizationContext {
    
    private final String nodeId;
    private final Instant syncStartTime;
    private final SynchronizationStrategy strategy;
    private final Map<String, Object> metadata;
    private final SynchronizationTrigger trigger;
    private final int attemptNumber;
    private final String requestId;
    
    // Sync statistics
    private volatile long networkLatencyMs;
    private volatile int policiesProcessed;
    private volatile int conflictsDetected;
    private volatile boolean isClusterMaster;
    
    public SynchronizationContext(
            String nodeId,
            SynchronizationStrategy strategy,
            SynchronizationTrigger trigger,
            int attemptNumber
    ) {
        this.nodeId = nodeId;
        this.syncStartTime = Instant.now();
        this.strategy = strategy;
        this.trigger = trigger;
        this.attemptNumber = attemptNumber;
        this.requestId = generateRequestId();
        this.metadata = new ConcurrentHashMap<>();
        this.networkLatencyMs = 0;
        this.policiesProcessed = 0;
        this.conflictsDetected = 0;
        this.isClusterMaster = false;
    }
    
    // Getters
    public String getNodeId() { return nodeId; }
    public Instant getSyncStartTime() { return syncStartTime; }
    public SynchronizationStrategy getStrategy() { return strategy; }
    public SynchronizationTrigger getTrigger() { return trigger; }
    public int getAttemptNumber() { return attemptNumber; }
    public String getRequestId() { return requestId; }
    public Map<String, Object> getMetadata() { return metadata; }
    
    // Performance metrics
    public long getNetworkLatencyMs() { return networkLatencyMs; }
    public void setNetworkLatencyMs(long networkLatencyMs) { this.networkLatencyMs = networkLatencyMs; }
    
    public int getPoliciesProcessed() { return policiesProcessed; }
    public void setPoliciesProcessed(int policiesProcessed) { this.policiesProcessed = policiesProcessed; }
    
    public int getConflictsDetected() { return conflictsDetected; }
    public void setConflictsDetected(int conflictsDetected) { this.conflictsDetected = conflictsDetected; }
    
    public boolean isClusterMaster() { return isClusterMaster; }
    public void setClusterMaster(boolean clusterMaster) { this.isClusterMaster = clusterMaster; }
    
    /**
     * Add metadata for the synchronization context
     */
    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }
    
    /**
     * Get metadata value
     */
    public Object getMetadata(String key) {
        return metadata.get(key);
    }
    
    /**
     * Check if this is a retry attempt
     */
    public boolean isRetryAttempt() {
        return attemptNumber > 1;
    }
    
    /**
     * Check if this sync was triggered by an external event
     */
    public boolean isEventTriggered() {
        return trigger == SynchronizationTrigger.EVENT_NOTIFICATION ||
               trigger == SynchronizationTrigger.WEBHOOK;
    }
    
    /**
     * Get elapsed time since sync started
     */
    public long getElapsedTimeMs() {
        return Instant.now().toEpochMilli() - syncStartTime.toEpochMilli();
    }
    
    /**
     * Check if sync is taking longer than expected
     */
    public boolean isSlowSync(long thresholdMs) {
        return getElapsedTimeMs() > thresholdMs;
    }
    
    /**
     * Create a summary of the synchronization context
     */
    public String getSummary() {
        return String.format(
            "SyncContext{nodeId='%s', strategy=%s, trigger=%s, attempt=%d, elapsed=%dms, policies=%d, conflicts=%d}",
            nodeId, strategy, trigger, attemptNumber, getElapsedTimeMs(), policiesProcessed, conflictsDetected
        );
    }
    
    private String generateRequestId() {
        return "sync-" + nodeId + "-" + syncStartTime.toEpochMilli() + "-" + attemptNumber;
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
    
    /**
     * What triggered this synchronization operation
     */
    public enum SynchronizationTrigger {
        SCHEDULED,          // Regular scheduled sync
        MANUAL,             // Manually triggered via API
        STARTUP,            // Triggered during plugin startup
        EVENT_NOTIFICATION, // Triggered by external event
        WEBHOOK,            // Triggered by webhook
        FAILOVER,           // Triggered by failover scenario
        RECOVERY            // Triggered during error recovery
    }
}