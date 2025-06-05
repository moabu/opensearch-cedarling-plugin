package org.opensearch.security.cedarling.tbac;

import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import java.util.List;

/**
 * Contains the results of TBAC policy evaluation for search hits
 */
public class TBACEvaluationResult {
    
    private final List<String> authorizedHitIds;
    private final List<TBACPolicyDecision> policyDecisions;
    private final SearchHit[] filteredSearchHits;
    private final TBACTokens tokens;
    private final long evaluationTimeMs;
    
    public TBACEvaluationResult(List<String> authorizedHitIds, 
                               List<TBACPolicyDecision> policyDecisions,
                               SearchHit[] filteredSearchHits,
                               TBACTokens tokens) {
        this.authorizedHitIds = authorizedHitIds;
        this.policyDecisions = policyDecisions;
        this.filteredSearchHits = filteredSearchHits;
        this.tokens = tokens;
        this.evaluationTimeMs = calculateTotalEvaluationTime(policyDecisions);
    }
    
    private long calculateTotalEvaluationTime(List<TBACPolicyDecision> decisions) {
        return decisions.stream()
            .mapToLong(TBACPolicyDecision::getEvaluationTimeMs)
            .sum();
    }
    
    public List<String> getAuthorizedHitIds() {
        return authorizedHitIds;
    }
    
    public List<TBACPolicyDecision> getPolicyDecisions() {
        return policyDecisions;
    }
    
    public SearchHit[] getFilteredSearchHits() {
        return filteredSearchHits;
    }
    
    public SearchHits getFilteredSearchHitsAsSearchHits() {
        return new SearchHits(filteredSearchHits, null, 0.0f);
    }
    
    public TBACTokens getTokens() {
        return tokens;
    }
    
    public int getTotalHitsEvaluated() {
        return policyDecisions.size();
    }
    
    public double getAuthorizationRate() {
        if (policyDecisions.isEmpty()) return 0.0;
        return (double) authorizedHitIds.size() / policyDecisions.size();
    }
    
    public int getPoliciesEvaluated() {
        return policyDecisions.size();
    }
    
    public long getAllowDecisions() {
        return policyDecisions.stream()
            .mapToLong(decision -> decision.isAllowed() ? 1 : 0)
            .sum();
    }
    
    public long getDenyDecisions() {
        return policyDecisions.size() - getAllowDecisions();
    }
    
    public long getEvaluationTimeMs() {
        return evaluationTimeMs;
    }
}