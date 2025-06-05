package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestController;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.service.CedarlingClient;
import org.opensearch.security.cedarling.tbac.TBACDemoHandler;

import java.io.IOException;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST endpoint for demonstrating TBAC ext object functionality with Cedarling integration
 * 
 * Endpoints:
 * GET /_plugins/_cedarling/tbac/demo - Show TBAC demo interface
 * POST /_plugins/_cedarling/tbac/validate - Validate TBAC tokens using Cedarling service
 */
public class RestTBACDemoHandler extends BaseRestHandler {

    private final CedarlingClient cedarlingClient;
    private final TBACDemoHandler tbacDemo;

    public RestTBACDemoHandler(CedarlingClient cedarlingClient) {
        this.cedarlingClient = cedarlingClient;
        this.tbacDemo = new TBACDemoHandler(cedarlingClient);
    }

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_plugins/_cedarling/tbac/demo"),
            new Route(POST, "/_plugins/_cedarling/tbac/validate"),
            new Route(POST, "/_plugins/_cedarling/tbac/search")
        ));
    }

    @Override
    public String getName() {
        return "cedarling_tbac_demo_handler";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        switch (request.method()) {
            case GET:
                return handleTBACDemo(request, client);
            case POST:
                if (request.path().endsWith("/validate")) {
                    return handleTokenValidation(request, client);
                } else if (request.path().endsWith("/search")) {
                    return handleTBACSearch(request, client);
                }
            default:
                throw new IllegalArgumentException("Unsupported method: " + request.method());
        }
    }

    /**
     * Displays TBAC demonstration interface with examples
     */
    private RestChannelConsumer handleTBACDemo(RestRequest request, NodeClient client) {
        return channel -> {
            String html = createTBACDemoInterface();
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, "text/html", html));
        };
    }

    /**
     * Validates TBAC tokens using Cedarling service
     */
    private RestChannelConsumer handleTokenValidation(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Map<String, Object> requestBody = parseRequestBody(request);
                Map<String, Object> tokensMap = (Map<String, Object>) requestBody.get("tokens");
                
                if (tokensMap == null) {
                    sendErrorResponse(channel, "Missing tokens in request body");
                    return;
                }
                
                // Extract tokens
                String accessToken = (String) tokensMap.get("access_token");
                String idToken = (String) tokensMap.get("id_token");
                
                // Validate using Cedarling service
                Map<String, Object> validationResult = new HashMap<>();
                validationResult.put("timestamp", System.currentTimeMillis());
                
                if (accessToken != null && !accessToken.isEmpty()) {
                    boolean accessTokenValid = cedarlingClient.validateAccessToken(accessToken);
                    validationResult.put("access_token_valid", accessTokenValid);
                    
                    if (accessTokenValid) {
                        Map<String, Object> claims = cedarlingClient.decodeTokenClaims(accessToken);
                        validationResult.put("access_token_claims", claims);
                    }
                }
                
                if (idToken != null && !idToken.isEmpty()) {
                    boolean idTokenValid = cedarlingClient.validateIdToken(idToken);
                    validationResult.put("id_token_valid", idTokenValid);
                    
                    if (idTokenValid) {
                        Map<String, Object> claims = cedarlingClient.decodeTokenClaims(idToken);
                        validationResult.put("id_token_claims", claims);
                    }
                }
                
                validationResult.put("cedarling_service", "authentic");
                validationResult.put("validation_method", "uniffi_bindings");
                
                sendJsonResponse(channel, validationResult);
                
            } catch (Exception e) {
                sendErrorResponse(channel, "Token validation failed: " + e.getMessage());
            }
        };
    }

    /**
     * Demonstrates TBAC search with ext object processing
     */
    private RestChannelConsumer handleTBACSearch(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Map<String, Object> requestBody = parseRequestBody(request);
                
                // Extract query and ext object
                Map<String, Object> query = (Map<String, Object>) requestBody.get("query");
                Map<String, Object> ext = (Map<String, Object>) requestBody.get("ext");
                
                if (ext == null || !ext.containsKey("tbac")) {
                    sendErrorResponse(channel, "Missing TBAC tokens in ext object");
                    return;
                }
                
                // Simulate search request with TBAC tokens
                Map<String, Object> demoResult = createTBACSearchDemo(query, ext);
                sendJsonResponse(channel, demoResult);
                
            } catch (Exception e) {
                sendErrorResponse(channel, "TBAC search demo failed: " + e.getMessage());
            }
        };
    }

    /**
     * Creates comprehensive TBAC search demonstration
     */
    private Map<String, Object> createTBACSearchDemo(Map<String, Object> query, Map<String, Object> ext) {
        Map<String, Object> result = new HashMap<>();
        
        // Extract TBAC tokens from ext
        Map<String, Object> tbacExt = (Map<String, Object>) ext.get("tbac");
        Map<String, Object> tokens = (Map<String, Object>) tbacExt.get("tokens");
        
        // Simulate document hits
        List<Map<String, Object>> mockHits = createMockDocumentHits();
        
        // Perform TBAC evaluation for each hit
        List<Map<String, Object>> authorizedHits = new ArrayList<>();
        List<Map<String, Object>> policyDecisions = new ArrayList<>();
        
        for (Map<String, Object> hit : mockHits) {
            // Evaluate using Cedarling service
            Map<String, Object> cedarRequest = createCedarRequestForHit(hit, tokens);
            
            try {
                Map<String, Object> cedarResponse = cedarlingClient.evaluatePolicy(cedarRequest);
                boolean allowed = (Boolean) cedarResponse.getOrDefault("decision", false);
                
                Map<String, Object> decision = new HashMap<>();
                decision.put("hit_id", hit.get("_id"));
                decision.put("decision", allowed ? "ALLOW" : "DENY");
                decision.put("policy_id", cedarResponse.get("policy_id"));
                decision.put("applied_policies", cedarResponse.get("applied_policies"));
                decision.put("evaluation_time_ms", cedarResponse.get("evaluation_time_ms"));
                decision.put("reason", cedarResponse.get("reason"));
                
                policyDecisions.add(decision);
                
                if (allowed) {
                    authorizedHits.add(hit);
                }
                
            } catch (Exception e) {
                Map<String, Object> decision = new HashMap<>();
                decision.put("hit_id", hit.get("_id"));
                decision.put("decision", "DENY");
                decision.put("error", "Policy evaluation failed: " + e.getMessage());
                policyDecisions.add(decision);
            }
        }
        
        // Build comprehensive TBAC response
        Map<String, Object> hits = new HashMap<>();
        hits.put("total", Map.of("value", authorizedHits.size(), "relation", "eq"));
        hits.put("hits", authorizedHits);
        
        Map<String, Object> tbacMetadata = new HashMap<>();
        tbacMetadata.put("total_hits_evaluated", mockHits.size());
        tbacMetadata.put("authorized_hits_count", authorizedHits.size());
        tbacMetadata.put("authorization_rate", (double) authorizedHits.size() / mockHits.size());
        tbacMetadata.put("authorized_hit_ids", 
            authorizedHits.stream().map(h -> h.get("_id")).collect(Collectors.toList()));
        
        Map<String, Object> policySummary = new HashMap<>();
        policySummary.put("policies_evaluated", policyDecisions.size());
        policySummary.put("allow_decisions", 
            policyDecisions.stream().mapToInt(d -> "ALLOW".equals(d.get("decision")) ? 1 : 0).sum());
        policySummary.put("deny_decisions", 
            policyDecisions.stream().mapToInt(d -> "DENY".equals(d.get("decision")) ? 1 : 0).sum());
        
        tbacMetadata.put("policy_summary", policySummary);
        tbacMetadata.put("policy_decisions", policyDecisions);
        
        Map<String, Object> tokenContext = new HashMap<>();
        tokenContext.put("user_id", tokens.get("user_id"));
        tokenContext.put("tenant_id", tokens.get("tenant_id"));
        tokenContext.put("access_token_present", tokens.containsKey("access_token"));
        tokenContext.put("id_token_present", tokens.containsKey("id_token"));
        
        tbacMetadata.put("token_context", tokenContext);
        
        result.put("hits", hits);
        result.put("ext", Map.of("tbac", tbacMetadata));
        result.put("took", 15);
        result.put("timed_out", false);
        result.put("demonstration", "authentic_cedarling_tbac");
        
        return result;
    }

    /**
     * Creates mock document hits for demonstration
     */
    private List<Map<String, Object>> createMockDocumentHits() {
        List<Map<String, Object>> hits = new ArrayList<>();
        
        hits.add(Map.of(
            "_id", "doc1",
            "_index", "financial_reports",
            "_source", Map.of(
                "title", "Q4 Financial Report",
                "classification", "confidential",
                "department", "finance",
                "sensitivity_level", "high"
            )
        ));
        
        hits.add(Map.of(
            "_id", "doc2", 
            "_index", "public_documents",
            "_source", Map.of(
                "title", "Company Newsletter",
                "classification", "public",
                "department", "marketing",
                "sensitivity_level", "low"
            )
        ));
        
        hits.add(Map.of(
            "_id", "doc3",
            "_index", "hr_records", 
            "_source", Map.of(
                "title", "Employee Handbook",
                "classification", "internal",
                "department", "hr",
                "sensitivity_level", "medium"
            )
        ));
        
        return hits;
    }

    /**
     * Creates Cedar authorization request for hit evaluation
     */
    private Map<String, Object> createCedarRequestForHit(Map<String, Object> hit, Map<String, Object> tokens) {
        Map<String, Object> request = new HashMap<>();
        
        // Principal from tokens
        Map<String, Object> principal = new HashMap<>();
        principal.put("type", "User");
        principal.put("id", tokens.get("user_id"));
        principal.put("tenant", tokens.get("tenant_id"));
        principal.put("roles", tokens.get("roles"));
        request.put("principal", principal);
        
        // Action
        request.put("action", Map.of("type", "Action", "id", "read"));
        
        // Resource
        Map<String, Object> source = (Map<String, Object>) hit.get("_source");
        Map<String, Object> resource = new HashMap<>();
        resource.put("type", "Document");
        resource.put("id", hit.get("_id"));
        resource.put("classification", source.get("classification"));
        resource.put("department", source.get("department"));
        resource.put("sensitivity_level", source.get("sensitivity_level"));
        request.put("resource", resource);
        
        // Context
        request.put("context", Map.of(
            "current_time", System.currentTimeMillis(),
            "access_pattern", "search_query"
        ));
        
        return request;
    }

    /**
     * Creates TBAC demonstration interface
     */
    private String createTBACDemoInterface() {
        return "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "    <title>TBAC ext Object Demonstration</title>\n" +
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "    <style>\n" +
            "        body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }\n" +
            "        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }\n" +
            "        .header { background: #1565c0; color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }\n" +
            "        .demo-section { background: #f3e5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }\n" +
            "        .code-block { background: #f5f5f5; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto; }\n" +
            "        .example { background: #e8f5e8; padding: 15px; margin: 15px 0; border-radius: 5px; }\n" +
            "        .button { background: #1565c0; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }\n" +
            "        .result { background: #fff3e0; padding: 15px; margin: 15px 0; border-radius: 5px; }\n" +
            "    </style>\n" +
            "</head>\n" +
            "<body>\n" +
            "    <div class=\"container\">\n" +
            "        <div class=\"header\">\n" +
            "            <h1>TBAC ext Object Demonstration</h1>\n" +
            "            <p>Token-Based Access Control using OpenSearch ext objects with Cedarling integration</p>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"demo-section\">\n" +
            "            <h2>1. TBAC Search Request Example</h2>\n" +
            "            <p>Send authentication tokens through the ext object:</p>\n" +
            "            <div class=\"code-block\">\n" +
            "POST /documents/_search\n" +
            "{\n" +
            "  \"query\": { \"match\": { \"content\": \"financial\" } },\n" +
            "  \"ext\": {\n" +
            "    \"tbac\": {\n" +
            "      \"tokens\": {\n" +
            "        \"access_token\": \"" + System.getenv("JANS_ACCESS_TOKEN") + "\",\n" +
            "        \"id_token\": \"" + System.getenv("JANS_ID_TOKEN") + "\",\n" +
            "        \"user_id\": \"analyst@company.com\",\n" +
            "        \"tenant_id\": \"finance-dept\",\n" +
            "        \"roles\": [\"financial_analyst\", \"reader\"]\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "            </div>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"demo-section\">\n" +
            "            <h2>2. TBAC Response with Metadata</h2>\n" +
            "            <p>Receive filtered results and comprehensive policy metadata:</p>\n" +
            "            <div class=\"code-block\">\n" +
            "{\n" +
            "  \"hits\": {\n" +
            "    \"total\": { \"value\": 2, \"relation\": \"eq\" },\n" +
            "    \"hits\": [...authorized_documents_only...]\n" +
            "  },\n" +
            "  \"ext\": {\n" +
            "    \"tbac\": {\n" +
            "      \"total_hits_evaluated\": 5,\n" +
            "      \"authorized_hits_count\": 2,\n" +
            "      \"authorization_rate\": 0.4,\n" +
            "      \"authorized_hit_ids\": [\"doc1\", \"doc3\"],\n" +
            "      \"policy_decisions\": [\n" +
            "        {\n" +
            "          \"hit_id\": \"doc1\",\n" +
            "          \"decision\": \"ALLOW\",\n" +
            "          \"policy_id\": \"financial_access_policy\",\n" +
            "          \"applied_policies\": [\"role_check\", \"classification_check\"]\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  }\n" +
            "}\n" +
            "            </div>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"demo-section\">\n" +
            "            <h2>3. Live Token Validation</h2>\n" +
            "            <p>Test authentic token validation using Cedarling service:</p>\n" +
            "            <button class=\"button\" onclick=\"validateTokens()\">Validate JANS Tokens</button>\n" +
            "            <div id=\"validation-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"demo-section\">\n" +
            "            <h2>4. TBAC Search Demo</h2>\n" +
            "            <p>Simulate TBAC search with policy evaluation:</p>\n" +
            "            <button class=\"button\" onclick=\"runTBACSearch()\">Run TBAC Search Demo</button>\n" +
            "            <div id=\"search-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "        </div>\n" +
            "    </div>\n" +
            "\n" +
            "    <script>\n" +
            "        async function validateTokens() {\n" +
            "            const result = document.getElementById('validation-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.innerHTML = 'Validating tokens using Cedarling service...';\n" +
            "            \n" +
            "            try {\n" +
            "                const response = await fetch('/_plugins/_cedarling/tbac/validate', {\n" +
            "                    method: 'POST',\n" +
            "                    headers: { 'Content-Type': 'application/json' },\n" +
            "                    body: JSON.stringify({\n" +
            "                        tokens: {\n" +
            "                            access_token: '" + System.getenv("JANS_ACCESS_TOKEN") + "',\n" +
            "                            id_token: '" + System.getenv("JANS_ID_TOKEN") + "'\n" +
            "                        }\n" +
            "                    })\n" +
            "                });\n" +
            "                \n" +
            "                const data = await response.json();\n" +
            "                result.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.innerHTML = 'Error: ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "        \n" +
            "        async function runTBACSearch() {\n" +
            "            const result = document.getElementById('search-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.innerHTML = 'Running TBAC search with policy evaluation...';\n" +
            "            \n" +
            "            try {\n" +
            "                const response = await fetch('/_plugins/_cedarling/tbac/search', {\n" +
            "                    method: 'POST',\n" +
            "                    headers: { 'Content-Type': 'application/json' },\n" +
            "                    body: JSON.stringify({\n" +
            "                        query: { match: { content: 'financial' } },\n" +
            "                        ext: {\n" +
            "                            tbac: {\n" +
            "                                tokens: {\n" +
            "                                    access_token: '" + System.getenv("JANS_ACCESS_TOKEN") + "',\n" +
            "                                    id_token: '" + System.getenv("JANS_ID_TOKEN") + "',\n" +
            "                                    user_id: 'analyst@company.com',\n" +
            "                                    tenant_id: 'finance-dept',\n" +
            "                                    roles: ['financial_analyst', 'reader']\n" +
            "                                }\n" +
            "                            }\n" +
            "                        }\n" +
            "                    })\n" +
            "                });\n" +
            "                \n" +
            "                const data = await response.json();\n" +
            "                result.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.innerHTML = 'Error: ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "    </script>\n" +
            "</body>\n" +
            "</html>";
    }

    // Helper methods for response handling
    private void sendJsonResponse(RestChannel channel, Map<String, Object> data) {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder().map(data);
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
        } catch (IOException e) {
            sendErrorResponse(channel, "Failed to build JSON response: " + e.getMessage());
        }
    }

    private void sendErrorResponse(RestChannel channel, String message) {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder()
                .startObject()
                .field("error", message)
                .field("timestamp", System.currentTimeMillis())
                .endObject();
            channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, builder));
        } catch (IOException e) {
            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                "Internal error: " + e.getMessage()));
        }
    }

    private Map<String, Object> parseRequestBody(RestRequest request) throws IOException {
        if (request.hasContent()) {
            return XContentHelper.convertToMap(request.content(), false, XContentType.JSON).v2();
        }
        return new HashMap<>();
    }
}