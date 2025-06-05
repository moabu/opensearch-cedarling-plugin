# Complete TBAC ext Object Demonstration

## Implementation Status

✅ **TBACMetadataHandler** - Core ext object processing  
✅ **TBACTokens** - Token extraction and validation  
✅ **TBACPolicyDecision** - Individual authorization decisions  
✅ **TBACEvaluationResult** - Comprehensive evaluation results  
✅ **PostQueryCedarlingFilter Integration** - Seamless ext object processing  
✅ **RestTBACDemoHandler** - Interactive demonstration endpoints  
✅ **Plugin Registration** - All components integrated into main plugin  

## Live Demonstration Endpoints

### 1. TBAC Demo Interface
```
GET /_plugins/_cedarling/tbac/demo
```
Interactive web interface showing TBAC functionality with live examples

### 2. Token Validation 
```
POST /_plugins/_cedarling/tbac/validate
```
Validates authentic Janssen tokens using Cedarling service

### 3. TBAC Search Demo
```
POST /_plugins/_cedarling/tbac/search
```
Demonstrates complete ext object workflow with policy evaluation

## Authentic Token Integration

The implementation uses real Janssen project tokens from environment variables:
- `JANS_ACCESS_TOKEN` - OAuth2 access token for authorization
- `JANS_ID_TOKEN` - OpenID Connect identity token for user context

## Complete Request/Response Example

### TBAC Search Request
```json
POST /documents/_search
{
  "query": {
    "match": { "content": "financial" }
  },
  "ext": {
    "tbac": {
      "tokens": {
        "access_token": "${JANS_ACCESS_TOKEN}",
        "id_token": "${JANS_ID_TOKEN}",
        "user_id": "analyst@company.com",
        "tenant_id": "finance-dept",
        "roles": ["financial_analyst", "reader"],
        "permissions": ["read:classified", "view:financial"]
      }
    }
  }
}
```

### TBAC Response with Comprehensive Metadata
```json
{
  "hits": {
    "total": { "value": 2, "relation": "eq" },
    "hits": [
      {
        "_id": "doc1",
        "_index": "financial_reports",
        "_source": {
          "title": "Q4 Financial Report",
          "classification": "confidential"
        }
      }
    ]
  },
  "ext": {
    "tbac": {
      "tbac_version": "1.0",
      "evaluation_timestamp": 1704442800000,
      "total_hits_evaluated": 5,
      "authorized_hits_count": 2,
      "authorization_rate": 0.4,
      "total_evaluation_time_ms": 12,
      "authorized_hit_ids": ["doc1", "doc3"],
      "policy_summary": {
        "policies_evaluated": 5,
        "allow_decisions": 2,
        "deny_decisions": 3,
        "average_evaluation_time_ms": 2.4
      },
      "token_context": {
        "access_token_present": true,
        "id_token_present": true,
        "user_id": "analyst@company.com",
        "tenant_id": "finance-dept",
        "user_roles": ["financial_analyst", "reader"],
        "user_permissions": ["read:classified", "view:financial"]
      },
      "detailed_policy_decisions": [
        {
          "hit_id": "doc1",
          "decision": "ALLOW",
          "policy_id": "financial_access_policy",
          "evaluation_time_ms": 2,
          "reason": "User has financial_analyst role and document classification allows access",
          "applied_policies": ["role_check", "classification_check", "department_access"]
        },
        {
          "hit_id": "doc2",
          "decision": "DENY", 
          "policy_id": "classification_policy",
          "evaluation_time_ms": 1,
          "reason": "Document classification 'top_secret' exceeds user clearance level",
          "applied_policies": ["classification_check"]
        }
      ]
    }
  }
}
```

## Implementation Architecture

### Token Extraction Flow
1. **Request Processing** - Extract ext.tbac.tokens from SearchRequest
2. **Token Validation** - Validate JWT signatures using Cedarling service  
3. **Context Building** - Create authorization context from token claims
4. **Policy Evaluation** - Evaluate each search hit against Cedar policies
5. **Response Building** - Return filtered hits with comprehensive metadata

### Cedar Policy Integration
```java
// Cedarling service integration
AuthorizationRequest cedarRequest = AuthorizationRequest.builder()
    .principal(tokens.getUserId())
    .action("read")
    .resource(createResourceContext(hit))
    .context(createEvaluationContext(tokens, hit))
    .build();

AuthorizationResponse response = cedarlingService.authorize(cedarRequest);
```

### Post-Query Filter Integration
```java
// TBAC processing in PostQueryCedarlingFilter
TBACTokens tbacTokens = tbacHandler.extractTokensFromRequest(searchRequest);

if (tbacTokens.hasAccessToken() || tbacTokens.hasIdToken()) {
    TBACEvaluationResult result = tbacHandler.evaluateHitsWithTBAC(
        hits, tbacTokens, searchRequest
    );
    
    SearchResponse modifiedResponse = tbacHandler.appendTBACMetadataToResponse(
        response, result
    );
    
    listener.onResponse(modifiedResponse);
}
```

## Security Features

### Token Validation
- **JWT Signature Verification** - Using Cedarling service validation
- **Token Expiration Checks** - Automatic expiry validation
- **Issuer Verification** - Trusted issuer validation
- **Audience Validation** - Token audience matching

### Policy Enforcement
- **Document-Level Authorization** - Each hit evaluated individually
- **Field-Level Security** - Granular field access control
- **Role-Based Access** - User role and permission evaluation
- **Classification-Based** - Document classification enforcement

### Audit Logging
- **Comprehensive Tracking** - All authorization decisions logged
- **Performance Metrics** - Evaluation time tracking
- **Policy Analytics** - Decision pattern analysis
- **User Access Patterns** - Behavioral monitoring

## Benefits of ext Object Approach

### 1. **Seamless Integration**
- Works with existing OpenSearch query structure
- No breaking changes to current APIs
- Backward compatible with non-TBAC queries

### 2. **Rich Metadata**
- Complete policy decision tracking
- Performance analytics included
- Comprehensive audit trail
- Real-time policy insights

### 3. **Flexible Token Support**
- Multiple token types (access, ID tokens)
- Custom claims and permissions
- Multi-tenant isolation
- Role hierarchy support

### 4. **Authentic Security**
- Real Cedarling policy engine integration
- Janssen project token validation
- Enterprise-grade authorization
- Production-ready implementation

## Testing the Implementation

### 1. Access Demo Interface
Visit: `http://localhost:5000/_plugins/_cedarling/tbac/demo`

### 2. Validate Tokens
```bash
curl -X POST "localhost:5000/_plugins/_cedarling/tbac/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "tokens": {
      "access_token": "'${JANS_ACCESS_TOKEN}'",
      "id_token": "'${JANS_ID_TOKEN}'"
    }
  }'
```

### 3. Run TBAC Search
```bash
curl -X POST "localhost:5000/_plugins/_cedarling/tbac/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": { "match": { "content": "financial" } },
    "ext": {
      "tbac": {
        "tokens": {
          "access_token": "'${JANS_ACCESS_TOKEN}'",
          "id_token": "'${JANS_ID_TOKEN}'",
          "user_id": "analyst@company.com",
          "tenant_id": "finance-dept",
          "roles": ["financial_analyst", "reader"]
        }
      }
    }
  }'
```

This implementation provides a complete, production-ready TBAC solution using OpenSearch ext objects with Cedarling integration and Janssen project tokens.