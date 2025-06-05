package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Request for Cedarling authorization
 */
public class CedarlingAuthorizationRequest extends ActionRequest {
    
    private String principalType;
    private String principalId;
    private String action;
    private String resourceType;
    private String resourceId;
    private String tenant;
    private String account;
    private List<String> roles;
    private Map<String, Object> context;
    
    public CedarlingAuthorizationRequest() {}
    
    public CedarlingAuthorizationRequest(StreamInput in) throws IOException {
        super(in);
        this.principalType = in.readString();
        this.principalId = in.readString();
        this.action = in.readString();
        this.resourceType = in.readString();
        this.resourceId = in.readString();
        this.tenant = in.readOptionalString();
        this.account = in.readOptionalString();
        this.roles = in.readOptionalStringList();
        this.context = in.readMap();
    }
    
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(principalType);
        out.writeString(principalId);
        out.writeString(action);
        out.writeString(resourceType);
        out.writeString(resourceId);
        out.writeOptionalString(tenant);
        out.writeOptionalString(account);
        out.writeOptionalStringCollection(roles);
        out.writeMap(context);
    }
    
    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        
        if (principalType == null || principalType.isEmpty()) {
            validationException = addValidationError("Principal type is required", validationException);
        }
        if (principalId == null || principalId.isEmpty()) {
            validationException = addValidationError("Principal ID is required", validationException);
        }
        if (action == null || action.isEmpty()) {
            validationException = addValidationError("Action is required", validationException);
        }
        if (resourceType == null || resourceType.isEmpty()) {
            validationException = addValidationError("Resource type is required", validationException);
        }
        if (resourceId == null || resourceId.isEmpty()) {
            validationException = addValidationError("Resource ID is required", validationException);
        }
        
        return validationException;
    }
    
    // Getters and setters
    public String getPrincipalType() { return principalType; }
    public void setPrincipalType(String principalType) { this.principalType = principalType; }
    
    public String getPrincipalId() { return principalId; }
    public void setPrincipalId(String principalId) { this.principalId = principalId; }
    
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    
    public String getResourceType() { return resourceType; }
    public void setResourceType(String resourceType) { this.resourceType = resourceType; }
    
    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }
    
    public String getTenant() { return tenant; }
    public void setTenant(String tenant) { this.tenant = tenant; }
    
    public String getAccount() { return account; }
    public void setAccount(String account) { this.account = account; }
    
    public List<String> getRoles() { return roles; }
    public void setRoles(List<String> roles) { this.roles = roles; }
    
    public Map<String, Object> getContext() { return context; }
    public void setContext(Map<String, Object> context) { this.context = context; }
}