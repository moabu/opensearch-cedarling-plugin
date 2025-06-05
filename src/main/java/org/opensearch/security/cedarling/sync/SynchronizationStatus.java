package org.opensearch.security.cedarling.sync;

import org.opensearch.security.cedarling.model.PolicyStoreSnapshot;

import java.time.Instant;

/**
 * Comprehensive status information for policy store synchronization
 * 
 * Provides detailed insights into synchronization health, performance,
 * and cluster-wide coordination for monitoring and administration.
 */
public class SynchronizationStatus {
    
    private final boolean enabled;
    private final SynchronizationStrategy currentStrategy;
    private final ConflictResolver.ConflictResolutionStrategy conflictStrategy;
    private final PolicyStoreSnapshot currentSnapshot;
    private final String lastKnownVersion;
    private final Instant lastSuccessfulSync;
    private final int consecutiveFailures;
    private final ClusterSyncStatus clusterStatus;
    
    public SynchronizationStatus(
            boolean enabled,
            SynchronizationStrategy currentStrategy,
            ConflictResolver.ConflictResolutionStrategy conflictStrategy,
            PolicyStoreSnapshot currentSnapshot,
            String lastKnownVersion,
            Instant lastSuccessfulSync,
            int consecutiveFailures,
            ClusterSyncStatus clusterStatus
    ) {
        this.enabled = enabled;
        this.currentStrategy = currentStrategy;
        this.conflictStrategy = conflictStrategy;
        this.currentSnapshot = currentSnapshot;
        this.lastKnownVersion = lastKnownVersion;
        this.lastSuccessfulSync = lastSuccessfulSync;
        this.consecutiveFailures = consecutiveFailures;
        this.clusterStatus = clusterStatus;
    }
    
    // Getters
    public boolean isEnabled() { return enabled; }
    public SynchronizationStrategy getCurrentStrategy() { return currentStrategy; }
    public ConflictResolver.ConflictResolutionStrategy getConflictStrategy() { return conflictStrategy; }
    public PolicyStoreSnapshot getCurrentSnapshot() { return currentSnapshot; }
    public String getLastKnownVersion() { return lastKnownVersion; }
    public Instant getLastSuccessfulSync() { return lastSuccessfulSync; }
    public int getConsecutiveFailures() { return consecutiveFailures; }
    public ClusterSyncStatus getClusterStatus() { return clusterStatus; }
    
    /**
     * Check if synchronization is healthy
     */
    public boolean isHealthy() {
        return enabled && 
               consecutiveFailures < 3 && 
               clusterStatus.getOverallHealth() != ClusterSyncStatus.SyncHealth.CRITICAL;
    }
    
    /**
     * Check if synchronization is currently active
     */
    public boolean isActive() {
        return enabled && clusterStatus.getSyncingNodes() > 0;
    }
    
    /**
     * Get the age of current policy snapshot in minutes
     */
    public long getSnapshotAgeMinutes() {
        if (currentSnapshot == null || currentSnapshot.getLastModified() == null) {
            return -1;
        }
        
        try {
            Instant snapshotTime = Instant.parse(currentSnapshot.getLastModified());
            return (Instant.now().toEpochMilli() - snapshotTime.toEpochMilli()) / (1000 * 60);
        } catch (Exception e) {
            return -1;
        }
    }
    
    /**
     * Get minutes since last successful sync
     */
    public long getMinutesSinceLastSync() {
        if (lastSuccessfulSync == null) {
            return -1;
        }
        
        return (Instant.now().toEpochMilli() - lastSuccessfulSync.toEpochMilli()) / (1000 * 60);
    }
    
    /**
     * Check if sync is overdue
     */
    public boolean isSyncOverdue(long intervalMinutes) {
        long minutesSinceSync = getMinutesSinceLastSync();
        return minutesSinceSync > intervalMinutes * 2; // Consider overdue if 2x interval
    }
    
    /**
     * Get overall synchronization health assessment
     */
    public SyncHealthStatus getOverallHealthStatus() {
        if (!enabled) {
            return SyncHealthStatus.DISABLED;
        }
        
        if (consecutiveFailures >= 5) {
            return SyncHealthStatus.CRITICAL;
        }
        
        if (consecutiveFailures >= 3) {
            return SyncHealthStatus.DEGRADED;
        }
        
        if (clusterStatus.getOverallHealth() == ClusterSyncStatus.SyncHealth.CRITICAL) {
            return SyncHealthStatus.CRITICAL;
        }
        
        if (clusterStatus.getOverallHealth() == ClusterSyncStatus.SyncHealth.DEGRADED) {
            return SyncHealthStatus.DEGRADED;
        }
        
        return SyncHealthStatus.HEALTHY;
    }
    
    /**
     * Get a human-readable summary of synchronization status
     */
    public String getSummary() {
        if (!enabled) {
            return "Policy synchronization is disabled";
        }
        
        StringBuilder summary = new StringBuilder();
        summary.append("Policy sync status: ").append(getOverallHealthStatus());
        
        if (currentSnapshot != null) {
            summary.append(" | Current version: ").append(lastKnownVersion);
            summary.append(" | Policies: ").append(currentSnapshot.getPolicies().size());
        }
        
        if (lastSuccessfulSync != null) {
            summary.append(" | Last sync: ").append(getMinutesSinceLastSync()).append(" minutes ago");
        }
        
        if (consecutiveFailures > 0) {
            summary.append(" | Failures: ").append(consecutiveFailures);
        }
        
        summary.append(" | Strategy: ").append(currentStrategy);
        summary.append(" | Cluster: ").append(clusterStatus.getOverallHealth());
        
        return summary.toString();
    }
    
    /**
     * Check if immediate attention is required
     */
    public boolean requiresAttention() {
        return getOverallHealthStatus() == SyncHealthStatus.CRITICAL ||
               consecutiveFailures >= 3 ||
               clusterStatus.requiresImmediateAttention();
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
    
    /**
     * Overall health status for synchronization
     */
    public enum SyncHealthStatus {
        HEALTHY,    // Everything working normally
        DEGRADED,   // Some issues but still functional
        CRITICAL,   // Serious problems requiring attention
        DISABLED    // Synchronization is disabled
    }
}