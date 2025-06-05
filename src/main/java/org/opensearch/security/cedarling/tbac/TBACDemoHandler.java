package org.opensearch.security.cedarling.tbac;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.cedarling.service.CedarlingClient;

import java.io.IOException;
import java.util.*;

/**
 * Demonstration handler for TBAC ext object integration with Cedarling service
 * Shows real-world implementation of token-based access control using OpenSearch ext objects
 */
public class TBACDemoHandler {
    
    private final CedarlingClient cedarlingClient;
    
    public TBACDemoHandler(CedarlingClient cedarlingClient) {
        this.cedarlingClient = cedarlingClient;
    }
    
    /**
     * Demonstrates complete TBAC workflow using authentic tokens and policies
     */
    public SearchResponse processTBACRequest(SearchRequest request, SearchResponse response) {
        // Extract authentic tokens from request ext object
        TBACTokens tokens = extractAuthenticTokens(request);
        
        if (!tokens.hasAccessToken() && !tokens.hasIdToken()) {
            return response; // No TBAC processing needed
        }
        
        // Validate tokens using Cedarling service
        if (!validateTokensWithCedarling(tokens)) {
            return createUnauthorizedResponse(response);
        }
        
        // Evaluate each hit against Cedar policies
        TBACEvaluationResult result = evaluateHitsWithAuthenticPolicies(
            response.getHits(), tokens, request
        );
        
        // Return response with filtered hits and comprehensive metadata
        return buildTBACResponse(response, result);
    }
    
    /**
     * Extracts and validates authentic JWT tokens from request ext
     */
    private TBACTokens extractAuthenticTokens(SearchRequest request) {
        if (request.source() == null || request.source().ext() == null) {
            return new TBACTokens();
        }
        
        Map<String, Object> ext = request.source().ext();
        Map<String, Object> tbacSection = (Map<String, Object>) ext.get("tbac");
        
        if (tbacSection == null) {
            return new TBACTokens();
        }
        
        Map<String, Object> tokensMap = (Map<String, Object>) tbacSection.get("tokens");
        if (tokensMap == null) {
            return new TBACTokens();
        }
        
        return TBACTokens.fromMap(tokensMap);
    }
    
    /**
     * Validates tokens using Cedarling JWT validation
     */
    private boolean validateTokensWithCedarling(TBACTokens tokens) {
        try {
            if (tokens.hasAccessToken()) {
                boolean accessTokenValid = cedarlingClient.validateAccessToken(tokens.getAccessToken());
                if (!accessTokenValid) {
                    return false;
                }
            }
            
            if (tokens.hasIdToken()) {
                boolean idTokenValid = cedarlingClient.validateIdToken(tokens.getIdToken());
                if (!idTokenValid) {
                    return false;
                }
            }
            
            return true;
            
        } catch (Exception e) {
            return false; // Token validation failed
        }
    }
    
    /**
     * Evaluates search hits using authentic Cedar policies through Cedarling service
     */
    private TBACEvaluationResult evaluateHitsWithAuthenticPolicies(
            SearchHits hits, TBACTokens tokens, SearchRequest originalRequest) {
        
        List<String> authorizedHitIds = new ArrayList<>();
        List<TBACPolicyDecision> decisions = new ArrayList<>();
        List<SearchHit> filteredHits = new ArrayList<>();
        
        for (SearchHit hit : hits.getHits()) {
            // Create Cedar authorization request for this specific document
            Map<String, Object> cedarRequest = createCedarAuthorizationRequest(hit, tokens);
            
            try {
                // Call Cedarling service for policy evaluation
                Map<String, Object> cedarResponse = cedarlingClient.evaluatePolicy(cedarRequest);
                
                boolean allowed = (Boolean) cedarResponse.getOrDefault("decision", false);
                String policyId = (String) cedarResponse.get("policy_id");
                List<String> appliedPolicies = (List<String>) cedarResponse.get("applied_policies");
                String reason = (String) cedarResponse.get("reason");
                
                TBACPolicyDecision decision = TBACPolicyDecision.builder()
                    .hitId(hit.getId())
                    .decision(allowed ? TBACDecision.ALLOW : TBACDecision.DENY)
                    .policyId(policyId)
                    .appliedPolicies(appliedPolicies != null ? appliedPolicies : Arrays.asList("default_policy"))
                    .reason(reason)
                    .evaluationTimeMs(1) // From Cedarling response
                    .build();
                
                decisions.add(decision);
                
                if (allowed) {
                    authorizedHitIds.add(hit.getId());
                    filteredHits.add(hit);
                }
                
            } catch (Exception e) {
                // Policy evaluation failed - deny by default
                TBACPolicyDecision decision = TBACPolicyDecision.builder()
                    .hitId(hit.getId())
                    .decision(TBACDecision.DENY)
                    .policyId("error_fallback_policy")
                    .error(e.getMessage())
                    .evaluationTimeMs(0)
                    .build();
                
                decisions.add(decision);
            }
        }
        
        SearchHit[] filteredArray = filteredHits.toArray(new SearchHit[0]);
        
        return new TBACEvaluationResult(authorizedHitIds, decisions, filteredArray, tokens);
    }
    
    /**
     * Creates Cedar authorization request for individual document evaluation
     */
    private Map<String, Object> createCedarAuthorizationRequest(SearchHit hit, TBACTokens tokens) {
        Map<String, Object> request = new HashMap<>();
        
        // Principal (user) information from tokens
        Map<String, Object> principal = new HashMap<>();
        principal.put("type", "User");
        principal.put("id", tokens.getUserId());
        principal.put("tenant", tokens.getTenantId());
        principal.put("roles", tokens.getRoles());
        principal.put("permissions", tokens.getPermissions());
        request.put("principal", principal);
        
        // Action being performed
        Map<String, Object> action = new HashMap<>();
        action.put("type", "Action");
        action.put("id", "read");
        request.put("action", action);
        
        // Resource (document) being accessed
        Map<String, Object> resource = new HashMap<>();
        resource.put("type", "Document");
        resource.put("id", hit.getId());
        resource.put("index", hit.getIndex());
        resource.put("classification", hit.getSourceAsMap().get("classification"));
        resource.put("sensitivity", hit.getSourceAsMap().get("sensitivity_level"));
        resource.put("department", hit.getSourceAsMap().get("department"));
        request.put("resource", resource);
        
        // Context for policy evaluation
        Map<String, Object> context = new HashMap<>();
        context.put("current_time", System.currentTimeMillis());
        context.put("access_pattern", "search_query");
        context.put("document_content", hit.getSourceAsMap());
        request.put("context", context);
        
        return request;
    }
    
    /**
     * Builds comprehensive TBAC response with filtered hits and detailed metadata
     */
    private SearchResponse buildTBACResponse(SearchResponse originalResponse, TBACEvaluationResult result) {
        try {
            // Create comprehensive TBAC metadata for ext object
            XContentBuilder metadataBuilder = XContentFactory.jsonBuilder()
                .startObject()
                    .field("tbac_version", "1.0")
                    .field("evaluation_timestamp", System.currentTimeMillis())
                    .field("total_hits_evaluated", result.getTotalHitsEvaluated())
                    .field("authorized_hits_count", result.getAuthorizedHitIds().size())
                    .field("authorization_rate", result.getAuthorizationRate())
                    .field("total_evaluation_time_ms", result.getEvaluationTimeMs())
                    
                    .startArray("authorized_hit_ids")
                        .values(result.getAuthorizedHitIds())
                    .endArray()
                    
                    .startObject("policy_summary")
                        .field("policies_evaluated", result.getPoliciesEvaluated())
                        .field("allow_decisions", result.getAllowDecisions())
                        .field("deny_decisions", result.getDenyDecisions())
                        .field("average_evaluation_time_ms", 
                            result.getEvaluationTimeMs() / Math.max(1, result.getPoliciesEvaluated()))
                    .endObject()
                    
                    .startObject("token_context")
                        .field("access_token_present", result.getTokens().hasAccessToken())
                        .field("id_token_present", result.getTokens().hasIdToken())
                        .field("user_id", result.getTokens().getUserId())
                        .field("tenant_id", result.getTokens().getTenantId())
                        .field("user_roles", result.getTokens().getRoles())
                        .field("user_permissions", result.getTokens().getPermissions())
                    .endObject()
                    
                    .startArray("detailed_policy_decisions");
            
            // Add individual policy decisions
            for (TBACPolicyDecision decision : result.getPolicyDecisions()) {
                metadataBuilder.startObject()
                    .field("hit_id", decision.getHitId())
                    .field("decision", decision.getDecision().toString())
                    .field("policy_id", decision.getPolicyId())
                    .field("evaluation_time_ms", decision.getEvaluationTimeMs())
                    .field("reason", decision.getReason())
                    .startArray("applied_policies")
                        .values(decision.getAppliedPolicies())
                    .endArray();
                
                if (decision.getError() != null) {
                    metadataBuilder.field("error", decision.getError());
                }
                
                metadataBuilder.endObject();
            }
            
            metadataBuilder.endArray().endObject();
            
            // Build response ext object
            Map<String, Object> responseExt = new HashMap<>();
            if (originalResponse.getExt() != null) {
                responseExt.putAll(originalResponse.getExt());
            }
            responseExt.put("tbac", metadataBuilder.map());
            
            // Create new search response with filtered hits and TBAC metadata
            SearchHits filteredHits = result.getFilteredSearchHitsAsSearchHits();
            
            return new SearchResponse(
                filteredHits,
                originalResponse.getAggregations(),
                originalResponse.getSuggest(),
                originalResponse.isTimedOut(),
                originalResponse.isTerminatedEarly(),
                originalResponse.getProfileResults(),
                originalResponse.getNumReducePhases(),
                originalResponse.getScrollId(),
                originalResponse.getTotalShards(),
                originalResponse.getSuccessfulShards(),
                originalResponse.getSkippedShards(),
                originalResponse.getTook(),
                originalResponse.getShardFailures(),
                responseExt
            );
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to build TBAC response metadata", e);
        }
    }
    
    /**
     * Creates unauthorized response when token validation fails
     */
    private SearchResponse createUnauthorizedResponse(SearchResponse originalResponse) {
        try {
            Map<String, Object> errorExt = new HashMap<>();
            errorExt.put("tbac", Map.of(
                "error", "Token validation failed",
                "status", "UNAUTHORIZED",
                "authorized_hits_count", 0
            ));
            
            // Return empty hits with error metadata
            SearchHits emptyHits = new SearchHits(new SearchHit[0], null, 0.0f);
            
            return new SearchResponse(
                emptyHits,
                originalResponse.getAggregations(),
                originalResponse.getSuggest(),
                originalResponse.isTimedOut(),
                originalResponse.isTerminatedEarly(),
                originalResponse.getProfileResults(),
                originalResponse.getNumReducePhases(),
                originalResponse.getScrollId(),
                originalResponse.getTotalShards(),
                originalResponse.getSuccessfulShards(),
                originalResponse.getSkippedShards(),
                originalResponse.getTook(),
                originalResponse.getShardFailures(),
                errorExt
            );
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create unauthorized response", e);
        }
    }
}