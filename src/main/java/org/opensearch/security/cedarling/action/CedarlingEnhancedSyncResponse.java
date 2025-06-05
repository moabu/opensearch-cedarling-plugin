package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/**
 * Response for enhanced policy store synchronization operations
 * 
 * Provides comprehensive status information, cluster state,
 * and operation results for monitoring and administration.
 */
public class CedarlingEnhancedSyncResponse extends ActionResponse implements ToXContentObject {
    
    private String action;
    private boolean success;
    private String message;
    private String currentVersion;
    private String syncStrategy;
    private String conflictStrategy;
    private Instant lastSyncTime;
    private int consecutiveFailures;
    private Map<String, Object> clusterStatus;
    private Map<String, Object> syncMetrics;
    private Map<String, Object> healthStatus;
    
    public CedarlingEnhancedSyncResponse() {
        // Default constructor for serialization
    }
    
    public CedarlingEnhancedSyncResponse(
            String action,
            boolean success,
            String message,
            String currentVersion,
            String syncStrategy,
            String conflictStrategy,
            Instant lastSyncTime,
            int consecutiveFailures,
            Map<String, Object> clusterStatus,
            Map<String, Object> syncMetrics,
            Map<String, Object> healthStatus
    ) {
        this.action = action;
        this.success = success;
        this.message = message;
        this.currentVersion = currentVersion;
        this.syncStrategy = syncStrategy;
        this.conflictStrategy = conflictStrategy;
        this.lastSyncTime = lastSyncTime;
        this.consecutiveFailures = consecutiveFailures;
        this.clusterStatus = clusterStatus;
        this.syncMetrics = syncMetrics;
        this.healthStatus = healthStatus;
    }
    
    public CedarlingEnhancedSyncResponse(StreamInput in) throws IOException {
        super(in);
        this.action = in.readString();
        this.success = in.readBoolean();
        this.message = in.readString();
        this.currentVersion = in.readOptionalString();
        this.syncStrategy = in.readOptionalString();
        this.conflictStrategy = in.readOptionalString();
        this.lastSyncTime = in.readOptionalInstant();
        this.consecutiveFailures = in.readInt();
        this.clusterStatus = in.readMap();
        this.syncMetrics = in.readMap();
        this.healthStatus = in.readMap();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(action);
        out.writeBoolean(success);
        out.writeString(message);
        out.writeOptionalString(currentVersion);
        out.writeOptionalString(syncStrategy);
        out.writeOptionalString(conflictStrategy);
        out.writeOptionalInstant(lastSyncTime);
        out.writeInt(consecutiveFailures);
        out.writeMap(clusterStatus);
        out.writeMap(syncMetrics);
        out.writeMap(healthStatus);
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        
        builder.field("action", action);
        builder.field("success", success);
        builder.field("message", message);
        
        if (currentVersion != null) {
            builder.field("current_version", currentVersion);
        }
        
        if (syncStrategy != null) {
            builder.field("sync_strategy", syncStrategy);
        }
        
        if (conflictStrategy != null) {
            builder.field("conflict_strategy", conflictStrategy);
        }
        
        if (lastSyncTime != null) {
            builder.field("last_sync_time", lastSyncTime.toString());
        }
        
        builder.field("consecutive_failures", consecutiveFailures);
        
        if (clusterStatus != null && !clusterStatus.isEmpty()) {
            builder.field("cluster_status", clusterStatus);
        }
        
        if (syncMetrics != null && !syncMetrics.isEmpty()) {
            builder.field("sync_metrics", syncMetrics);
        }
        
        if (healthStatus != null && !healthStatus.isEmpty()) {
            builder.field("health_status", healthStatus);
        }
        
        builder.endObject();
        return builder;
    }
    
    // Getters
    public String getAction() { return action; }
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public String getCurrentVersion() { return currentVersion; }
    public String getSyncStrategy() { return syncStrategy; }
    public String getConflictStrategy() { return conflictStrategy; }
    public Instant getLastSyncTime() { return lastSyncTime; }
    public int getConsecutiveFailures() { return consecutiveFailures; }
    public Map<String, Object> getClusterStatus() { return clusterStatus; }
    public Map<String, Object> getSyncMetrics() { return syncMetrics; }
    public Map<String, Object> getHealthStatus() { return healthStatus; }
}