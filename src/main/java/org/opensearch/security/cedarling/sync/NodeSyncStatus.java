package org.opensearch.security.cedarling.sync;

import java.time.Instant;

/**
 * Tracks the synchronization status of individual nodes in the cluster
 * 
 * Provides detailed information about each node's policy store state
 * for distributed coordination and monitoring purposes.
 */
public class NodeSyncStatus {
    
    private final String nodeId;
    private final String currentVersion;
    private final Instant lastSyncTime;
    private final SyncState syncState;
    private final String lastError;
    private final long syncDurationMs;
    private final int syncAttempts;
    
    public NodeSyncStatus(String nodeId, String currentVersion, Instant lastSyncTime, SyncState syncState) {
        this(nodeId, currentVersion, lastSyncTime, syncState, null, 0, 1);
    }
    
    public NodeSyncStatus(
            String nodeId,
            String currentVersion,
            Instant lastSyncTime,
            SyncState syncState,
            String lastError,
            long syncDurationMs,
            int syncAttempts
    ) {
        this.nodeId = nodeId;
        this.currentVersion = currentVersion;
        this.lastSyncTime = lastSyncTime;
        this.syncState = syncState;
        this.lastError = lastError;
        this.syncDurationMs = syncDurationMs;
        this.syncAttempts = syncAttempts;
    }
    
    // Getters
    public String getNodeId() { return nodeId; }
    public String getCurrentVersion() { return currentVersion; }
    public Instant getLastSyncTime() { return lastSyncTime; }
    public SyncState getSyncState() { return syncState; }
    public String getLastError() { return lastError; }
    public long getSyncDurationMs() { return syncDurationMs; }
    public int getSyncAttempts() { return syncAttempts; }
    
    /**
     * Check if the node is currently synchronized
     */
    public boolean isSynchronized() {
        return syncState == SyncState.SYNCHRONIZED;
    }
    
    /**
     * Check if the node requires attention
     */
    public boolean requiresAttention() {
        return syncState == SyncState.FAILED || 
               syncState == SyncState.CONFLICT ||
               syncAttempts > 3;
    }
    
    /**
     * Check if sync is stale (older than threshold)
     */
    public boolean isStale(long thresholdMinutes) {
        return lastSyncTime.isBefore(Instant.now().minusSeconds(thresholdMinutes * 60));
    }
    
    /**
     * Create an updated status with new information
     */
    public NodeSyncStatus withUpdate(String newVersion, SyncState newState, String error, long duration) {
        return new NodeSyncStatus(
            nodeId,
            newVersion,
            Instant.now(),
            newState,
            error,
            duration,
            newState == SyncState.FAILED ? syncAttempts + 1 : 1
        );
    }
    
    @Override
    public String toString() {
        return String.format(
            "NodeSyncStatus{nodeId='%s', version='%s', state=%s, lastSync=%s, attempts=%d}",
            nodeId, currentVersion, syncState, lastSyncTime, syncAttempts
        );
    }
    
    /**
     * Possible synchronization states for a node
     */
    public enum SyncState {
        SYNCHRONIZED,    // Node is up to date with latest policy version
        SYNCING,         // Node is currently performing synchronization
        PENDING,         // Node is queued for synchronization
        FAILED,          // Last synchronization attempt failed
        CONFLICT,        // Node has conflicts that need resolution
        OFFLINE,         // Node is not reachable
        EXCLUDED         // Node is excluded from synchronization
    }
}