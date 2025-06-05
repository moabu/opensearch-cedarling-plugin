package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Request for policy synchronization operations
 */
public class CedarlingPolicySyncRequest extends ActionRequest {
    
    private String action;
    
    public CedarlingPolicySyncRequest() {}
    
    public CedarlingPolicySyncRequest(String action) {
        this.action = action;
    }
    
    public CedarlingPolicySyncRequest(StreamInput in) throws IOException {
        super(in);
        this.action = in.readString();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(action);
    }
    
    @Override
    public ActionRequestValidationException validate() {
        if (action == null || action.trim().isEmpty()) {
            ActionRequestValidationException validationException = new ActionRequestValidationException();
            validationException.addValidationError("action cannot be null or empty");
            return validationException;
        }
        return null;
    }
    
    public String getAction() {
        return action;
    }
    
    public void setAction(String action) {
        this.action = action;
    }
}