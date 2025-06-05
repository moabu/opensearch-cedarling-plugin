package org.opensearch.security.cedarling.model;

import java.util.List;
import java.util.Map;

/**
 * Authorization request model for Cedarling integration
 * 
 * Represents a Token-Based Access Control (TBAC) authorization request
 * following the Cedar policy language structure.
 */
public class AuthorizationRequest {
    
    private final String principalType;
    private final String principalId;
    private final String action;
    private final String resourceType;
    private final String resourceId;
    private final String tenant;
    private final String account;
    private final String resourceTenant;
    private final String resourceAccount;
    private final List<String> roles;
    private final Map<String, Object> context;
    
    public AuthorizationRequest(Builder builder) {
        this.principalType = builder.principalType;
        this.principalId = builder.principalId;
        this.action = builder.action;
        this.resourceType = builder.resourceType;
        this.resourceId = builder.resourceId;
        this.tenant = builder.tenant;
        this.account = builder.account;
        this.resourceTenant = builder.resourceTenant;
        this.resourceAccount = builder.resourceAccount;
        this.roles = builder.roles;
        this.context = builder.context;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String principalType;
        private String principalId;
        private String action;
        private String resourceType;
        private String resourceId;
        private String tenant;
        private String account;
        private String resourceTenant;
        private String resourceAccount;
        private List<String> roles;
        private Map<String, Object> context;
        
        public Builder principal(String type, String id) {
            this.principalType = type;
            this.principalId = id;
            return this;
        }
        
        public Builder action(String action) {
            this.action = action;
            return this;
        }
        
        public Builder resource(String type, String id) {
            this.resourceType = type;
            this.resourceId = id;
            return this;
        }
        
        public Builder tenant(String tenant) {
            this.tenant = tenant;
            return this;
        }
        
        public Builder account(String account) {
            this.account = account;
            return this;
        }
        
        public Builder resourceTenant(String tenant) {
            this.resourceTenant = tenant;
            return this;
        }
        
        public Builder resourceAccount(String account) {
            this.resourceAccount = account;
            return this;
        }
        
        public Builder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }
        
        public Builder context(Map<String, Object> context) {
            this.context = context;
            return this;
        }
        
        public AuthorizationRequest build() {
            if (principalType == null || principalId == null) {
                throw new IllegalArgumentException("Principal type and ID are required");
            }
            if (action == null) {
                throw new IllegalArgumentException("Action is required");
            }
            if (resourceType == null || resourceId == null) {
                throw new IllegalArgumentException("Resource type and ID are required");
            }
            return new AuthorizationRequest(this);
        }
    }
    
    // Getters
    public String getPrincipalType() { return principalType; }
    public String getPrincipalId() { return principalId; }
    public String getAction() { return action; }
    public String getResourceType() { return resourceType; }
    public String getResourceId() { return resourceId; }
    public String getTenant() { return tenant; }
    public String getAccount() { return account; }
    public String getResourceTenant() { return resourceTenant; }
    public String getResourceAccount() { return resourceAccount; }
    public List<String> getRoles() { return roles; }
    public Map<String, Object> getContext() { return context; }
    
    @Override
    public String toString() {
        return String.format("AuthorizationRequest{principal=%s:%s, action=%s, resource=%s:%s, tenant=%s, account=%s}",
                principalType, principalId, action, resourceType, resourceId, tenant, account);
    }
}