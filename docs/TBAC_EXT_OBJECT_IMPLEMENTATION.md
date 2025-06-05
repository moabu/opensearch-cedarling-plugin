# TBAC ext Object Implementation for OpenSearch Cedarling Plugin

## Overview

This document describes the implementation of Token-Based Access Control (TBAC) using OpenSearch's `ext` object for metadata transmission between query and response phases in the Cedarling Security Plugin.

## Architecture

The solution leverages OpenSearch's `ext` object capability to:
1. **Send authentication tokens with queries** via the request `ext` object
2. **Receive authorization metadata in responses** via the response `ext` object
3. **Track which hits passed policy evaluation** through comprehensive metadata

## Key Components

### 1. TBACMetadataHandler
Main orchestrator for ext object processing:
- Extracts tokens from search request ext
- Evaluates hits using Cedarling service
- Appends authorization metadata to response ext

### 2. TBACTokens
Represents authentication context:
```java
{
  "access_token": "eyJ...",
  "id_token": "eyJ...", 
  "user_id": "user123",
  "tenant_id": "tenant456",
  "roles": ["admin", "reader"],
  "permissions": ["read:documents", "write:reports"],
  "claims": { "custom_claim": "value" }
}
```

### 3. PostQueryCedarlingFilter Integration
Enhanced filter that:
- Detects TBAC tokens in request ext
- Performs policy evaluation on search hits
- Returns filtered results with metadata

## Usage Examples

### Query with TBAC Tokens

```json
POST /documents/_search
{
  "query": {
    "match": { "content": "sensitive" }
  },
  "ext": {
    "tbac": {
      "tokens": {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        "user_id": "john.doe@company.com",
        "tenant_id": "acme-corp",
        "roles": ["analyst", "reader"],
        "permissions": ["read:classified", "view:financial"]
      }
    }
  }
}
```

### Response with TBAC Metadata

```json
{
  "hits": {
    "total": { "value": 2, "relation": "eq" },
    "hits": [
      {
        "_id": "doc1",
        "_source": { "title": "Public Report" }
      }
    ]
  },
  "ext": {
    "tbac": {
      "total_hits_evaluated": 5,
      "authorized_hits_count": 2,
      "authorization_rate": 0.4,
      "authorized_hit_ids": ["doc1", "doc3"],
      "policy_summary": {
        "policies_evaluated": 5,
        "allow_decisions": 2,
        "deny_decisions": 3,
        "evaluation_time_ms": 12
      },
      "token_context": {
        "access_token_present": true,
        "id_token_present": true,
        "user_id": "john.doe@company.com",
        "tenant_id": "acme-corp"
      },
      "policy_decisions": [
        {
          "hit_id": "doc1",
          "decision": "ALLOW",
          "policy_id": "document_access_policy",
          "evaluation_time_ms": 2,
          "applied_policies": ["base_access", "classification_check"]
        },
        {
          "hit_id": "doc2", 
          "decision": "DENY",
          "policy_id": "classification_policy",
          "evaluation_time_ms": 3,
          "applied_policies": ["classification_check"]
        }
      ]
    }
  }
}
```

## Implementation Details

### Token Extraction Process

```java
public TBACTokens extractTokensFromRequest(SearchRequest searchRequest) {
    if (searchRequest.source() == null || searchRequest.source().ext() == null) {
        return new TBACTokens();
    }
    
    Map<String, Object> extMap = searchRequest.source().ext();
    Map<String, Object> tbacExt = (Map<String, Object>) extMap.get("tbac");
    
    if (tbacExt == null) {
        return new TBACTokens();
    }
    
    Map<String, Object> tokensMap = (Map<String, Object>) tbacExt.get("tokens");
    return TBACTokens.fromMap(tokensMap != null ? tokensMap : new HashMap<>());
}
```

### Policy Evaluation Integration

```java
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
        
        // Evaluate policy using Cedarling service
        AuthorizationResponse response = cedarlingService.authorize(authRequest);
        
        TBACPolicyDecision decision = TBACPolicyDecision.builder()
            .hitId(hit.getId())
            .decision(response.isAllowed() ? TBACDecision.ALLOW : TBACDecision.DENY)
            .policyId(response.getPolicyId())
            .appliedPolicies(response.getAppliedPolicies())
            .build();
            
        policyDecisions.add(decision);
        
        if (decision.isAllowed()) {
            authorizedHitIds.add(hit.getId());
            filteredHits[filteredCount++] = hit;
        }
    }
    
    return new TBACEvaluationResult(authorizedHitIds, policyDecisions, 
                                   Arrays.copyOf(filteredHits, filteredCount), tokens);
}
```

### Response Metadata Appending

```java
public SearchResponse appendTBACMetadataToResponse(
        SearchResponse searchResponse, 
        TBACEvaluationResult evaluationResult) {
    
    // Build comprehensive TBAC metadata
    XContentBuilder tbacMetadata = XContentFactory.jsonBuilder()
        .startObject()
            .field("total_hits_evaluated", evaluationResult.getTotalHitsEvaluated())
            .field("authorized_hits_count", evaluationResult.getAuthorizedHitIds().size())
            .field("authorization_rate", evaluationResult.getAuthorizationRate())
            .startArray("authorized_hit_ids")
                .values(evaluationResult.getAuthorizedHitIds())
            .endArray()
            // ... additional metadata fields
        .endObject();
    
    // Create new response with filtered hits and metadata
    Map<String, Object> responseExt = new HashMap<>();
    if (searchResponse.getExt() != null) {
        responseExt.putAll(searchResponse.getExt());
    }
    responseExt.put("tbac", tbacMetadata.map());
    
    return new SearchResponse(
        evaluationResult.getFilteredSearchHits(),
        searchResponse.getAggregations(),
        // ... other response components
        responseExt
    );
}
```

## Security Considerations

### Token Validation
- Tokens are validated through Cedarling service
- JWT signature verification against trusted issuers
- Token expiration and revocation checks
- Tenant isolation enforcement

### Audit Logging
- All TBAC evaluations are comprehensively logged
- Policy decisions tracked per document
- Performance metrics recorded
- User access patterns monitored

### Error Handling
- Graceful degradation when tokens are invalid
- Fallback to traditional context-based filtering
- Detailed error reporting in ext metadata

## Performance Optimization

### Parallel Evaluation
- Document policy evaluations run in parallel
- Cedarling service calls optimized for batch processing
- Result caching for repeated policy patterns

### Minimal Response Overhead
- Metadata only included when TBAC tokens present
- Selective policy decision details based on configuration
- Efficient JSON serialization

## Integration with Existing Features

### Compatibility
- Works alongside existing OpenSearch Security features
- Maintains backward compatibility with non-TBAC queries
- Integrates with existing audit and monitoring systems

### Cedar Policy Engine
- Uses Cedarling UniFFI bindings
- Supports complex policy hierarchies
- Real-time policy updates and synchronization

## Benefits

1. **Comprehensive Authorization**: Every search hit evaluated against Cedar policies
2. **Rich Metadata**: Detailed information about policy decisions
3. **Token-Based Security**: Leverages modern authentication patterns
4. **Audit Transparency**: Complete traceability of access decisions
5. **Performance Monitoring**: Built-in metrics for policy evaluation efficiency

This implementation provides a robust foundation for implementing fine-grained, token-based access control in OpenSearch while maintaining compatibility with existing security mechanisms.