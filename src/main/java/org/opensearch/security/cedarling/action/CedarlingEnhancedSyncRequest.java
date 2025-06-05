package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Request for enhanced policy store synchronization operations
 * 
 * Supports various synchronization actions including status queries,
 * forced synchronization, strategy updates, and cluster coordination.
 */
public class CedarlingEnhancedSyncRequest extends ActionRequest {
    
    private String action;
    private String strategy;
    private String conflictResolution;
    private boolean includeClusterState;
    private boolean detailedStatus;
    
    public CedarlingEnhancedSyncRequest() {
        // Default constructor for serialization
    }
    
    public CedarlingEnhancedSyncRequest(
            String action,
            String strategy,
            String conflictResolution,
            boolean includeClusterState,
            boolean detailedStatus
    ) {
        this.action = action;
        this.strategy = strategy;
        this.conflictResolution = conflictResolution;
        this.includeClusterState = includeClusterState;
        this.detailedStatus = detailedStatus;
    }
    
    public CedarlingEnhancedSyncRequest(StreamInput in) throws IOException {
        super(in);
        this.action = in.readString();
        this.strategy = in.readOptionalString();
        this.conflictResolution = in.readOptionalString();
        this.includeClusterState = in.readBoolean();
        this.detailedStatus = in.readBoolean();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(action);
        out.writeOptionalString(strategy);
        out.writeOptionalString(conflictResolution);
        out.writeBoolean(includeClusterState);
        out.writeBoolean(detailedStatus);
    }
    
    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        
        if (action == null || action.isEmpty()) {
            validationException = new ActionRequestValidationException();
            validationException.addValidationError("action is required");
        }
        
        return validationException;
    }
    
    // Getters
    public String getAction() { return action; }
    public String getStrategy() { return strategy; }
    public String getConflictResolution() { return conflictResolution; }
    public boolean isIncludeClusterState() { return includeClusterState; }
    public boolean isDetailedStatus() { return detailedStatus; }
    
    // Setters
    public void setAction(String action) { this.action = action; }
    public void setStrategy(String strategy) { this.strategy = strategy; }
    public void setConflictResolution(String conflictResolution) { this.conflictResolution = conflictResolution; }
    public void setIncludeClusterState(boolean includeClusterState) { this.includeClusterState = includeClusterState; }
    public void setDetailedStatus(boolean detailedStatus) { this.detailedStatus = detailedStatus; }
}