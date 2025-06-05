package org.opensearch.security.cedarling.tbac;

import java.util.List;

/**
 * Represents a policy decision for a specific search hit in TBAC evaluation
 */
public class TBACPolicyDecision {
    
    private final String hitId;
    private final TBACDecision decision;
    private final String policyId;
    private final long evaluationTimeMs;
    private final List<String> appliedPolicies;
    private final String reason;
    private final String error;
    
    private TBACPolicyDecision(Builder builder) {
        this.hitId = builder.hitId;
        this.decision = builder.decision;
        this.policyId = builder.policyId;
        this.evaluationTimeMs = builder.evaluationTimeMs;
        this.appliedPolicies = builder.appliedPolicies;
        this.reason = builder.reason;
        this.error = builder.error;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public String getHitId() {
        return hitId;
    }
    
    public TBACDecision getDecision() {
        return decision;
    }
    
    public boolean isAllowed() {
        return decision == TBACDecision.ALLOW;
    }
    
    public String getPolicyId() {
        return policyId;
    }
    
    public long getEvaluationTimeMs() {
        return evaluationTimeMs;
    }
    
    public List<String> getAppliedPolicies() {
        return appliedPolicies;
    }
    
    public String getReason() {
        return reason;
    }
    
    public String getError() {
        return error;
    }
    
    public static class Builder {
        private String hitId;
        private TBACDecision decision;
        private String policyId;
        private long evaluationTimeMs;
        private List<String> appliedPolicies;
        private String reason;
        private String error;
        
        public Builder hitId(String hitId) {
            this.hitId = hitId;
            return this;
        }
        
        public Builder decision(TBACDecision decision) {
            this.decision = decision;
            return this;
        }
        
        public Builder policyId(String policyId) {
            this.policyId = policyId;
            return this;
        }
        
        public Builder evaluationTimeMs(long evaluationTimeMs) {
            this.evaluationTimeMs = evaluationTimeMs;
            return this;
        }
        
        public Builder appliedPolicies(List<String> appliedPolicies) {
            this.appliedPolicies = appliedPolicies;
            return this;
        }
        
        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }
        
        public Builder error(String error) {
            this.error = error;
            return this;
        }
        
        public TBACPolicyDecision build() {
            return new TBACPolicyDecision(this);
        }
    }
}

enum TBACDecision {
    ALLOW,
    DENY
}