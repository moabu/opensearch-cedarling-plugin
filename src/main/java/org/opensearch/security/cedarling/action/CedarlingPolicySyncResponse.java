package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer.SynchronizationStatus;

import java.io.IOException;
import java.time.Instant;

/**
 * Response for policy synchronization operations
 */
public class CedarlingPolicySyncResponse extends ActionResponse implements ToXContentObject {
    
    private String action;
    private boolean success;
    private String message;
    private SynchronizationStatus syncStatus;
    
    public CedarlingPolicySyncResponse() {}
    
    public CedarlingPolicySyncResponse(String action, boolean success, String message, SynchronizationStatus syncStatus) {
        this.action = action;
        this.success = success;
        this.message = message;
        this.syncStatus = syncStatus;
    }
    
    public CedarlingPolicySyncResponse(StreamInput in) throws IOException {
        super(in);
        this.action = in.readString();
        this.success = in.readBoolean();
        this.message = in.readOptionalString();
        
        // Read sync status if present
        if (in.readBoolean()) {
            boolean enabled = in.readBoolean();
            long syncIntervalSeconds = in.readLong();
            String currentVersion = in.readOptionalString();
            Instant lastSync = in.readOptionalInstant();
            int policyCount = in.readInt();
            boolean healthy = in.readBoolean();
            
            this.syncStatus = new SynchronizationStatus(enabled, syncIntervalSeconds, currentVersion, lastSync, policyCount, healthy);
        }
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(action);
        out.writeBoolean(success);
        out.writeOptionalString(message);
        
        // Write sync status if present
        if (syncStatus != null) {
            out.writeBoolean(true);
            out.writeBoolean(syncStatus.isEnabled());
            out.writeLong(syncStatus.getSyncIntervalSeconds());
            out.writeOptionalString(syncStatus.getCurrentVersion());
            out.writeOptionalInstant(syncStatus.getLastSync());
            out.writeInt(syncStatus.getPolicyCount());
            out.writeBoolean(syncStatus.isHealthy());
        } else {
            out.writeBoolean(false);
        }
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("action", action);
        builder.field("success", success);
        
        if (message != null) {
            builder.field("message", message);
        }
        
        if (syncStatus != null) {
            builder.startObject("synchronization");
            builder.field("enabled", syncStatus.isEnabled());
            builder.field("sync_interval_seconds", syncStatus.getSyncIntervalSeconds());
            builder.field("healthy", syncStatus.isHealthy());
            builder.field("policy_count", syncStatus.getPolicyCount());
            
            if (syncStatus.getCurrentVersion() != null) {
                builder.field("current_version", syncStatus.getCurrentVersion());
            }
            
            if (syncStatus.getLastSync() != null) {
                builder.field("last_sync", syncStatus.getLastSync().toString());
            }
            
            builder.endObject();
        }
        
        builder.endObject();
        return builder;
    }
    
    // Getters
    public String getAction() { return action; }
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public SynchronizationStatus getSyncStatus() { return syncStatus; }
}