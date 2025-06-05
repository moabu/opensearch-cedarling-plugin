package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Request for Cedarling policy management operations
 */
public class CedarlingPolicyRequest extends ActionRequest {
    
    private String operation; // list, get, create, update, delete
    private String policyId;
    private String policyContent;
    private String description;
    
    public CedarlingPolicyRequest() {}
    
    public CedarlingPolicyRequest(StreamInput in) throws IOException {
        super(in);
        this.operation = in.readString();
        this.policyId = in.readOptionalString();
        this.policyContent = in.readOptionalString();
        this.description = in.readOptionalString();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(operation);
        out.writeOptionalString(policyId);
        out.writeOptionalString(policyContent);
        out.writeOptionalString(description);
    }
    
    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        
        if (operation == null || operation.isEmpty()) {
            validationException = addValidationError("Operation is required", validationException);
        }
        
        if ("get".equals(operation) || "update".equals(operation) || "delete".equals(operation)) {
            if (policyId == null || policyId.isEmpty()) {
                validationException = addValidationError("Policy ID is required for " + operation + " operation", validationException);
            }
        }
        
        if ("create".equals(operation) || "update".equals(operation)) {
            if (policyContent == null || policyContent.isEmpty()) {
                validationException = addValidationError("Policy content is required for " + operation + " operation", validationException);
            }
        }
        
        return validationException;
    }
    
    // Getters and setters
    public String getOperation() { return operation; }
    public void setOperation(String operation) { this.operation = operation; }
    
    public String getPolicyId() { return policyId; }
    public void setPolicyId(String policyId) { this.policyId = policyId; }
    
    public String getPolicyContent() { return policyContent; }
    public void setPolicyContent(String policyContent) { this.policyContent = policyContent; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}