package org.opensearch.security.cedarling.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * AuthZen evaluation response model that matches the authentic jans-cedarling service
 * Based on the actual Cedarling Flask sidecar implementation
 */
public class AuthZenEvaluationResponse {
    
    @JsonProperty("decision")
    private boolean decision;
    
    @JsonProperty("context")
    private Map<String, Object> context;
    
    public AuthZenEvaluationResponse() {}
    
    public AuthZenEvaluationResponse(boolean decision, Map<String, Object> context) {
        this.decision = decision;
        this.context = context;
    }
    
    public boolean isDecision() { return decision; }
    public void setDecision(boolean decision) { this.decision = decision; }
    
    public Map<String, Object> getContext() { return context; }
    public void setContext(Map<String, Object> context) { this.context = context; }
}