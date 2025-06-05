package org.opensearch.security.cedarling.tbac;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.service.CedarlingService;

import java.io.IOException;
import java.util.*;

/**
 * Handles Token-Based Access Control (TBAC) metadata integration with OpenSearch ext object
 * 
 * This class implements the solution for sending extra metadata with OpenSearch queries
 * that contains authentication tokens and policy evaluation results through the ext object.
 * 
 * Key features:
 * - Extracts tokens from query ext object
 * - Performs policy evaluation on search hits using Cedarling service
 * - Appends authorization metadata back to response ext object
 * - Tracks which hits passed policy evaluation
 */
public class TBACMetadataHandler {
    
    private static final String EXT_TBAC_KEY = "tbac";
    private static final String EXT_TOKENS_KEY = "tokens";
    private static final String EXT_POLICY_RESULTS_KEY = "policy_results";
    private static final String EXT_AUTHORIZED_HITS_KEY = "authorized_hits";
    
    private final CedarlingService cedarlingService;
    
    public TBACMetadataHandler(CedarlingService cedarlingService) {
        this.cedarlingService = cedarlingService;
    }
    
    /**
     * Extracts TBAC tokens from the search request ext object
     * 
     * @param searchRequest The incoming search request
     * @return TBACTokens containing extracted authentication tokens
     */
    public TBACTokens extractTokensFromRequest(SearchRequest searchRequest) {
        if (searchRequest.source() == null || searchRequest.source().ext() == null) {
            return new TBACTokens();
        }
        
        Map<String, Object> extMap = searchRequest.source().ext();
        Map<String, Object> tbacExt = (Map<String, Object>) extMap.get(EXT_TBAC_KEY);
        
        if (tbacExt == null) {
            return new TBACTokens();
        }
        
        Map<String, Object> tokensMap = (Map<String, Object>) tbacExt.get(EXT_TOKENS_KEY);
        
        return TBACTokens.fromMap(tokensMap != null ? tokensMap : new HashMap<>());
    }
    
    /**
     * Processes search hits through TBAC policy evaluation using Cedarling service
     * 
     * @param searchHits The search hits to evaluate
     * @param tokens The TBAC tokens for authorization
     * @param originalRequest The original search request for context
     * @return TBACEvaluationResult containing authorized hits and policy decisions
     */
    public TBACEvaluationResult evaluateHitsWithTBAC(
            SearchHits searchHits, 
            TBACTokens tokens, 
            SearchRequest originalRequest) {
        
        List<String> authorizedHitIds = new ArrayList<>();
        List<TBACPolicyDecision> policyDecisions = new ArrayList<>();
        SearchHit[] filteredHits = new SearchHit[searchHits.getHits().length];
        int filteredCount = 0;
        
        for (SearchHit hit : searchHits.getHits()) {
            // Create authorization request for this specific hit
            AuthorizationRequest authRequest = createAuthorizationRequest(hit, tokens, originalRequest);
            
            // Evaluate policy for this hit using Cedarling engine
            TBACPolicyDecision decision = evaluatePolicyForHit(authRequest, hit);
            policyDecisions.add(decision);
            
            if (decision.isAllowed()) {
                authorizedHitIds.add(hit.getId());
                filteredHits[filteredCount++] = hit;
            }
        }
        
        // Resize filtered hits array
        SearchHit[] finalFilteredHits = Arrays.copyOf(filteredHits, filteredCount);
        
        return new TBACEvaluationResult(
            authorizedHitIds, 
            policyDecisions, 
            finalFilteredHits,
            tokens
        );
    }
    
    /**
     * Appends TBAC metadata to the search response ext object
     * 
     * @param searchResponse The search response to modify
     * @param evaluationResult The TBAC evaluation results
     * @return Modified search response with TBAC metadata in ext
     */
    public SearchResponse appendTBACMetadataToResponse(
            SearchResponse searchResponse, 
            TBACEvaluationResult evaluationResult) {
        
        try {
            // Build TBAC metadata for ext object
            XContentBuilder tbacMetadata = XContentFactory.jsonBuilder()
                .startObject()
                    .field("total_hits_evaluated", evaluationResult.getTotalHitsEvaluated())
                    .field("authorized_hits_count", evaluationResult.getAuthorizedHitIds().size())
                    .field("authorization_rate", evaluationResult.getAuthorizationRate())
                    .startArray("authorized_hit_ids")
                        .values(evaluationResult.getAuthorizedHitIds())
                    .endArray()
                    .startObject("policy_summary")
                        .field("policies_evaluated", evaluationResult.getPoliciesEvaluated())
                        .field("allow_decisions", evaluationResult.getAllowDecisions())
                        .field("deny_decisions", evaluationResult.getDenyDecisions())
                        .field("evaluation_time_ms", evaluationResult.getEvaluationTimeMs())
                    .endObject()
                    .startObject("token_context")
                        .field("access_token_present", evaluationResult.getTokens().hasAccessToken())
                        .field("id_token_present", evaluationResult.getTokens().hasIdToken())
                        .field("user_id", evaluationResult.getTokens().getUserId())
                        .field("tenant_id", evaluationResult.getTokens().getTenantId())
                    .endObject()
                    .startArray("policy_decisions")
                    .endArray()
                .endObject();
            
            // Add detailed policy decisions
            for (TBACPolicyDecision decision : evaluationResult.getPolicyDecisions()) {
                tbacMetadata.startObject()
                    .field("hit_id", decision.getHitId())
                    .field("decision", decision.getDecision().toString())
                    .field("policy_id", decision.getPolicyId())
                    .field("evaluation_time_ms", decision.getEvaluationTimeMs())
                    .startArray("applied_policies")
                        .values(decision.getAppliedPolicies())
                    .endArray()
                .endObject();
            }
            
            // Create new search response with TBAC metadata in ext
            Map<String, Object> responseExt = new HashMap<>();
            if (searchResponse.getExt() != null) {
                responseExt.putAll(searchResponse.getExt());
            }
            responseExt.put(EXT_TBAC_KEY, tbacMetadata.map());
            
            // Return modified search response with filtered hits and TBAC metadata
            return new SearchResponse(
                evaluationResult.getFilteredSearchHits(),
                searchResponse.getAggregations(),
                searchResponse.getSuggest(),
                searchResponse.isTimedOut(),
                searchResponse.isTerminatedEarly(),
                searchResponse.getProfileResults(),
                searchResponse.getNumReducePhases(),
                searchResponse.getScrollId(),
                searchResponse.getTotalShards(),
                searchResponse.getSuccessfulShards(),
                searchResponse.getSkippedShards(),
                searchResponse.getTook(),
                searchResponse.getShardFailures(),
                responseExt
            );
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to build TBAC metadata for response ext", e);
        }
    }
    
    /**
     * Creates authorization request for individual search hit evaluation
     */
    private AuthorizationRequest createAuthorizationRequest(
            SearchHit hit, 
            TBACTokens tokens, 
            SearchRequest originalRequest) {
        
        return AuthorizationRequest.builder()
            .principal(tokens.getUserId())
            .action("read")
            .resource(createResourceContext(hit, originalRequest))
            .context(createEvaluationContext(tokens, hit))
            .build();
    }
    
    /**
     * Evaluates Cedar policy for a specific search hit using Cedarling service
     */
    private TBACPolicyDecision evaluatePolicyForHit(AuthorizationRequest authRequest, SearchHit hit) {
        long startTime = System.currentTimeMillis();
        
        try {
            // Use Cedarling service for policy evaluation
            AuthorizationResponse response = cedarlingService.authorize(authRequest);
            
            long evaluationTime = System.currentTimeMillis() - startTime;
            
            return TBACPolicyDecision.builder()
                .hitId(hit.getId())
                .decision(response.isAllowed() ? TBACDecision.ALLOW : TBACDecision.DENY)
                .policyId(response.getPolicyId())
                .evaluationTimeMs(evaluationTime)
                .appliedPolicies(response.getAppliedPolicies())
                .reason(response.getReason())
                .build();
                
        } catch (Exception e) {
            long evaluationTime = System.currentTimeMillis() - startTime;
            return TBACPolicyDecision.builder()
                .hitId(hit.getId())
                .decision(TBACDecision.DENY)
                .policyId("error_fallback_policy")
                .evaluationTimeMs(evaluationTime)
                .error(e.getMessage())
                .build();
        }
    }
    
    /**
     * Creates resource context for policy evaluation
     */
    private Map<String, Object> createResourceContext(SearchHit hit, SearchRequest originalRequest) {
        Map<String, Object> context = new HashMap<>();
        context.put("document_id", hit.getId());
        context.put("index", hit.getIndex());
        context.put("type", hit.getType());
        context.put("source", hit.getSourceAsMap());
        context.put("query", originalRequest.source().query());
        return context;
    }
    
    /**
     * Creates evaluation context from tokens and hit data
     */
    private Map<String, Object> createEvaluationContext(TBACTokens tokens, SearchHit hit) {
        Map<String, Object> context = new HashMap<>();
        context.put("user_id", tokens.getUserId());
        context.put("tenant_id", tokens.getTenantId());
        context.put("roles", tokens.getRoles());
        context.put("permissions", tokens.getPermissions());
        context.put("document_classification", hit.getSourceAsMap().get("classification"));
        context.put("access_time", System.currentTimeMillis());
        return context;
    }
}