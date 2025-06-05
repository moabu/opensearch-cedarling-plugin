package org.opensearch.security.cedarling.model;

/**
 * Authorization response from Cedarling policy decision point
 */
public class AuthorizationResponse {
    
    private final boolean allowed;
    private final String reason;
    private final Object diagnostics;
    
    public AuthorizationResponse(boolean allowed, String reason, Object diagnostics) {
        this.allowed = allowed;
        this.reason = reason;
        this.diagnostics = diagnostics;
    }
    
    public boolean isAllowed() {
        return allowed;
    }
    
    public String getReason() {
        return reason;
    }
    
    public Object getDiagnostics() {
        return diagnostics;
    }
    
    @Override
    public String toString() {
        return String.format("AuthorizationResponse{allowed=%s, reason='%s'}", allowed, reason);
    }
}