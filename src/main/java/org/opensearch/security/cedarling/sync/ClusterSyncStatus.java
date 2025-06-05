package org.opensearch.security.cedarling.sync;

import java.time.Instant;
import java.util.Map;

/**
 * Overall synchronization status for the entire OpenSearch cluster
 * 
 * Provides a comprehensive view of policy store synchronization
 * across all nodes for monitoring and administration purposes.
 */
public class ClusterSyncStatus {
    
    private final boolean distributedSyncEnabled;
    private final String currentLeader;
    private final String clusterPolicyVersion;
    private final Map<String, NodeSyncStatus> nodeStatuses;
    private final boolean isLocalNodeLeader;
    private final Instant statusTimestamp;
    
    public ClusterSyncStatus(
            boolean distributedSyncEnabled,
            String currentLeader,
            String clusterPolicyVersion,
            Map<String, NodeSyncStatus> nodeStatuses,
            boolean isLocalNodeLeader
    ) {
        this.distributedSyncEnabled = distributedSyncEnabled;
        this.currentLeader = currentLeader;
        this.clusterPolicyVersion = clusterPolicyVersion;
        this.nodeStatuses = nodeStatuses;
        this.isLocalNodeLeader = isLocalNodeLeader;
        this.statusTimestamp = Instant.now();
    }
    
    // Getters
    public boolean isDistributedSyncEnabled() { return distributedSyncEnabled; }
    public String getCurrentLeader() { return currentLeader; }
    public String getClusterPolicyVersion() { return clusterPolicyVersion; }
    public Map<String, NodeSyncStatus> getNodeStatuses() { return nodeStatuses; }
    public boolean isLocalNodeLeader() { return isLocalNodeLeader; }
    public Instant getStatusTimestamp() { return statusTimestamp; }
    
    /**
     * Get the total number of nodes in the cluster
     */
    public int getTotalNodes() {
        return nodeStatuses.size();
    }
    
    /**
     * Get the number of synchronized nodes
     */
    public int getSynchronizedNodes() {
        return (int) nodeStatuses.values().stream()
            .mapToLong(status -> status.isSynchronized() ? 1 : 0)
            .sum();
    }
    
    /**
     * Get the number of nodes that failed synchronization
     */
    public int getFailedNodes() {
        return (int) nodeStatuses.values().stream()
            .mapToLong(status -> status.getSyncState() == NodeSyncStatus.SyncState.FAILED ? 1 : 0)
            .sum();
    }
    
    /**
     * Get the number of nodes currently syncing
     */
    public int getSyncingNodes() {
        return (int) nodeStatuses.values().stream()
            .mapToLong(status -> status.getSyncState() == NodeSyncStatus.SyncState.SYNCING ? 1 : 0)
            .sum();
    }
    
    /**
     * Get the number of nodes with conflicts
     */
    public int getConflictNodes() {
        return (int) nodeStatuses.values().stream()
            .mapToLong(status -> status.getSyncState() == NodeSyncStatus.SyncState.CONFLICT ? 1 : 0)
            .sum();
    }
    
    /**
     * Check if the cluster is fully synchronized
     */
    public boolean isClusterSynchronized() {
        return getSynchronizedNodes() == getTotalNodes() && getTotalNodes() > 0;
    }
    
    /**
     * Check if the cluster has any critical issues
     */
    public boolean hasCriticalIssues() {
        return getFailedNodes() > 0 || getConflictNodes() > 0;
    }
    
    /**
     * Get the synchronization health percentage
     */
    public double getSyncHealthPercentage() {
        if (getTotalNodes() == 0) return 100.0;
        return (double) getSynchronizedNodes() / getTotalNodes() * 100.0;
    }
    
    /**
     * Get overall cluster sync health status
     */
    public SyncHealth getOverallHealth() {
        if (!distributedSyncEnabled) {
            return SyncHealth.DISABLED;
        }
        
        if (isClusterSynchronized()) {
            return SyncHealth.HEALTHY;
        }
        
        double healthPercentage = getSyncHealthPercentage();
        
        if (healthPercentage >= 80.0) {
            return SyncHealth.MOSTLY_HEALTHY;
        } else if (healthPercentage >= 50.0) {
            return SyncHealth.DEGRADED;
        } else {
            return SyncHealth.CRITICAL;
        }
    }
    
    /**
     * Get a summary description of the cluster sync status
     */
    public String getSummary() {
        if (!distributedSyncEnabled) {
            return "Distributed synchronization is disabled";
        }
        
        return String.format(
            "Cluster sync status: %s (%.1f%% healthy) - %d/%d nodes synchronized, Leader: %s",
            getOverallHealth(),
            getSyncHealthPercentage(),
            getSynchronizedNodes(),
            getTotalNodes(),
            currentLeader != null ? currentLeader : "none"
        );
    }
    
    /**
     * Check if immediate attention is required
     */
    public boolean requiresImmediateAttention() {
        return getOverallHealth() == SyncHealth.CRITICAL || getFailedNodes() > getTotalNodes() / 2;
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
    
    /**
     * Overall health status of cluster synchronization
     */
    public enum SyncHealth {
        HEALTHY,         // All nodes synchronized
        MOSTLY_HEALTHY,  // 80%+ nodes synchronized
        DEGRADED,        // 50-80% nodes synchronized
        CRITICAL,        // <50% nodes synchronized
        DISABLED         // Distributed sync is disabled
    }
}