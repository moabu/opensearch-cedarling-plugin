package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestController;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.service.CedarlingClient;
import org.opensearch.security.cedarling.audit.AuditLogger;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for data-based authorization policies with Cedarling UniFFI integration
 * 
 * Endpoints:
 * GET /_plugins/_cedarling/data-policies - Interface for policy management
 * POST /_plugins/_cedarling/data-policies/authorize - Authorize data access
 * POST /_plugins/_cedarling/data-policies/schema - Create/update schema
 * POST /_plugins/_cedarling/data-policies/policy - Create/update policy
 * GET /_plugins/_cedarling/data-policies/analytics - Policy analytics
 */
public class RestDataPolicyAuthorizationHandler extends BaseRestHandler {

    private final CedarlingClient cedarlingClient;
    private final AuditLogger auditLogger;

    public RestDataPolicyAuthorizationHandler(CedarlingClient cedarlingClient, AuditLogger auditLogger) {
        this.cedarlingClient = cedarlingClient;
        this.auditLogger = auditLogger;
    }

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_plugins/_cedarling/data-policies"),
            new Route(POST, "/_plugins/_cedarling/data-policies/authorize"),
            new Route(POST, "/_plugins/_cedarling/data-policies/schema"),
            new Route(POST, "/_plugins/_cedarling/data-policies/policy"),
            new Route(PUT, "/_plugins/_cedarling/data-policies/policy/{id}"),
            new Route(DELETE, "/_plugins/_cedarling/data-policies/policy/{id}"),
            new Route(GET, "/_plugins/_cedarling/data-policies/analytics")
        ));
    }

    @Override
    public String getName() {
        return "cedarling_data_policy_authorization_handler";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        switch (request.method()) {
            case GET:
                if (request.path().endsWith("/analytics")) {
                    return handleAnalytics(request, client);
                } else {
                    return handleInterface(request, client);
                }
            case POST:
                if (request.path().endsWith("/authorize")) {
                    return handleAuthorization(request, client);
                } else if (request.path().endsWith("/schema")) {
                    return handleSchemaCreation(request, client);
                } else if (request.path().endsWith("/policy")) {
                    return handlePolicyCreation(request, client);
                }
            case PUT:
                return handlePolicyUpdate(request, client);
            case DELETE:
                return handlePolicyDeletion(request, client);
            default:
                throw new IllegalArgumentException("Unsupported method: " + request.method());
        }
    }

    /**
     * Displays data-based authorization policy interface
     */
    private RestChannelConsumer handleInterface(RestRequest request, NodeClient client) {
        return channel -> {
            String html = createDataPolicyInterface();
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, "text/html", html));
        };
    }

    /**
     * Authorize data access using Cedarling UniFFI service
     */
    private RestChannelConsumer handleAuthorization(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Map<String, Object> requestBody = parseRequestBody(request);
                
                // Extract authorization parameters
                String principal = (String) requestBody.get("principal");
                String action = (String) requestBody.get("action");
                Map<String, Object> resource = (Map<String, Object>) requestBody.get("resource");
                Map<String, Object> context = (Map<String, Object>) requestBody.get("context");
                
                if (principal == null || action == null || resource == null) {
                    sendErrorResponse(channel, "Missing required authorization parameters");
                    return;
                }
                
                // Create Cedarling authorization request using UniFFI bindings
                Map<String, Object> cedarRequest = new HashMap<>();
                cedarRequest.put("principal", createPrincipalEntity(principal));
                cedarRequest.put("action", createActionEntity(action));
                cedarRequest.put("resource", createResourceEntity(resource));
                cedarRequest.put("context", context != null ? context : new HashMap<>());
                
                // Call Cedarling service through UniFFI
                Map<String, Object> authResult = cedarlingClient.evaluateDataBasedPolicy(cedarRequest);
                
                // Enhance result with metadata
                authResult.put("timestamp", System.currentTimeMillis());
                authResult.put("authorization_method", "cedarling_uniffi");
                authResult.put("request_id", generateRequestId());
                
                // Log authorization decision
                auditLogger.logDataBasedAuthorization(principal, action, resource, authResult);
                
                sendJsonResponse(channel, authResult);
                
            } catch (Exception e) {
                auditLogger.logError("Data-based authorization failed", e);
                sendErrorResponse(channel, "Authorization failed: " + e.getMessage());
            }
        };
    }

    /**
     * Create or update Cedar schema using Cedarling UniFFI
     */
    private RestChannelConsumer handleSchemaCreation(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Map<String, Object> requestBody = parseRequestBody(request);
                
                String schemaName = (String) requestBody.get("name");
                String schemaContent = (String) requestBody.get("schema");
                String description = (String) requestBody.get("description");
                
                if (schemaName == null || schemaContent == null) {
                    sendErrorResponse(channel, "Missing schema name or content");
                    return;
                }
                
                // Validate and create schema using Cedarling UniFFI
                Map<String, Object> schemaRequest = new HashMap<>();
                schemaRequest.put("name", schemaName);
                schemaRequest.put("schema", schemaContent);
                schemaRequest.put("description", description);
                schemaRequest.put("version", "1.0");
                
                Map<String, Object> schemaResult = cedarlingClient.createSchema(schemaRequest);
                
                // Enhance with metadata
                schemaResult.put("created_at", System.currentTimeMillis());
                schemaResult.put("created_via", "uniffi_bindings");
                
                // Log schema creation
                auditLogger.logSchemaOperation("CREATE", schemaName, schemaResult);
                
                sendJsonResponse(channel, schemaResult);
                
            } catch (Exception e) {
                auditLogger.logError("Schema creation failed", e);
                sendErrorResponse(channel, "Schema creation failed: " + e.getMessage());
            }
        };
    }

    /**
     * Create Cedar policy using Cedarling UniFFI
     */
    private RestChannelConsumer handlePolicyCreation(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                Map<String, Object> requestBody = parseRequestBody(request);
                
                String policyId = (String) requestBody.get("id");
                String policyContent = (String) requestBody.get("policy");
                String description = (String) requestBody.get("description");
                String effect = (String) requestBody.get("effect");
                
                if (policyId == null || policyContent == null) {
                    sendErrorResponse(channel, "Missing policy ID or content");
                    return;
                }
                
                // Create policy using Cedarling UniFFI bindings
                Map<String, Object> policyRequest = new HashMap<>();
                policyRequest.put("id", policyId);
                policyRequest.put("policy", policyContent);
                policyRequest.put("description", description);
                policyRequest.put("effect", effect != null ? effect : "permit");
                policyRequest.put("created_at", System.currentTimeMillis());
                
                Map<String, Object> policyResult = cedarlingClient.createPolicy(policyRequest);
                
                // Enhance with metadata
                policyResult.put("policy_engine", "cedarling_uniffi");
                policyResult.put("status", "active");
                
                // Log policy creation
                auditLogger.logPolicyOperation("CREATE", policyId, policyResult);
                
                sendJsonResponse(channel, policyResult);
                
            } catch (Exception e) {
                auditLogger.logError("Policy creation failed", e);
                sendErrorResponse(channel, "Policy creation failed: " + e.getMessage());
            }
        };
    }

    /**
     * Update existing Cedar policy
     */
    private RestChannelConsumer handlePolicyUpdate(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                String policyId = request.param("id");
                Map<String, Object> requestBody = parseRequestBody(request);
                
                if (policyId == null) {
                    sendErrorResponse(channel, "Missing policy ID");
                    return;
                }
                
                requestBody.put("id", policyId);
                requestBody.put("updated_at", System.currentTimeMillis());
                
                Map<String, Object> updateResult = cedarlingClient.updatePolicy(requestBody);
                
                auditLogger.logPolicyOperation("UPDATE", policyId, updateResult);
                sendJsonResponse(channel, updateResult);
                
            } catch (Exception e) {
                auditLogger.logError("Policy update failed", e);
                sendErrorResponse(channel, "Policy update failed: " + e.getMessage());
            }
        };
    }

    /**
     * Delete Cedar policy
     */
    private RestChannelConsumer handlePolicyDeletion(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                String policyId = request.param("id");
                
                if (policyId == null) {
                    sendErrorResponse(channel, "Missing policy ID");
                    return;
                }
                
                Map<String, Object> deleteResult = cedarlingClient.deletePolicy(policyId);
                
                auditLogger.logPolicyOperation("DELETE", policyId, deleteResult);
                sendJsonResponse(channel, deleteResult);
                
            } catch (Exception e) {
                auditLogger.logError("Policy deletion failed", e);
                sendErrorResponse(channel, "Policy deletion failed: " + e.getMessage());
            }
        };
    }

    /**
     * Return policy analytics using Cedarling UniFFI
     */
    private RestChannelConsumer handleAnalytics(RestRequest request, NodeClient client) {
        return channel -> {
            try {
                // Get analytics from Cedarling service
                Map<String, Object> analytics = cedarlingClient.getPolicyAnalytics();
                
                // Enhance with additional metrics
                analytics.put("timestamp", System.currentTimeMillis());
                analytics.put("analytics_source", "cedarling_uniffi");
                
                sendJsonResponse(channel, analytics);
                
            } catch (Exception e) {
                auditLogger.logError("Analytics retrieval failed", e);
                sendErrorResponse(channel, "Analytics retrieval failed: " + e.getMessage());
            }
        };
    }

    /**
     * Creates the data-based authorization policy interface
     */
    private String createDataPolicyInterface() {
        return "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head>\n" +
            "    <title>Data-Based Authorization Policies</title>\n" +
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "    <style>\n" +
            "        body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }\n" +
            "        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }\n" +
            "        .header { background: #1565c0; color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }\n" +
            "        .section { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #1565c0; }\n" +
            "        .form-group { margin: 15px 0; }\n" +
            "        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }\n" +
            "        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }\n" +
            "        .form-group textarea { height: 120px; font-family: monospace; }\n" +
            "        .button { background: #1565c0; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }\n" +
            "        .button:hover { background: #0d47a1; }\n" +
            "        .result { background: #fff3e0; padding: 15px; margin: 15px 0; border-radius: 5px; border: 1px solid #ff9800; }\n" +
            "        .success { background: #e8f5e8; border-color: #4caf50; }\n" +
            "        .error { background: #ffebee; border-color: #f44336; }\n" +
            "        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }\n" +
            "        .code-block { background: #f5f5f5; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto; }\n" +
            "        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }\n" +
            "    </style>\n" +
            "</head>\n" +
            "<body>\n" +
            "    <div class=\"container\">\n" +
            "        <div class=\"header\">\n" +
            "            <h1>Data-Based Authorization Policies</h1>\n" +
            "            <p>Create schemas and policies for data access control using Cedarling UniFFI</p>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"grid\">\n" +
            "            <div class=\"section\">\n" +
            "                <h2>1. Schema Management</h2>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"schema-name\">Schema Name:</label>\n" +
            "                    <input type=\"text\" id=\"schema-name\" placeholder=\"DocumentSchema\">\n" +
            "                </div>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"schema-description\">Description:</label>\n" +
            "                    <input type=\"text\" id=\"schema-description\" placeholder=\"Schema for document access control\">\n" +
            "                </div>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"schema-content\">Cedar Schema:</label>\n" +
            "                    <textarea id=\"schema-content\" placeholder=\"entity User = { name: String, department: String, clearance: Long };\">entity User = {\n" +
            "  name: String,\n" +
            "  department: String,\n" +
            "  clearance: Long,\n" +
            "  roles: Set<String>\n" +
            "};\n" +
            "\n" +
            "entity Document = {\n" +
            "  title: String,\n" +
            "  classification: String,\n" +
            "  department: String,\n" +
            "  sensitivity_level: Long\n" +
            "};\n" +
            "\n" +
            "action read appliesTo {\n" +
            "  principal: User,\n" +
            "  resource: Document\n" +
            "};</textarea>\n" +
            "                </div>\n" +
            "                <button class=\"button\" onclick=\"createSchema()\">Create Schema</button>\n" +
            "                <div id=\"schema-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "            </div>\n" +
            "\n" +
            "            <div class=\"section\">\n" +
            "                <h2>2. Policy Creation</h2>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"policy-id\">Policy ID:</label>\n" +
            "                    <input type=\"text\" id=\"policy-id\" placeholder=\"document_access_policy\">\n" +
            "                </div>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"policy-description\">Description:</label>\n" +
            "                    <input type=\"text\" id=\"policy-description\" placeholder=\"Controls document access based on classification\">\n" +
            "                </div>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"policy-effect\">Effect:</label>\n" +
            "                    <select id=\"policy-effect\">\n" +
            "                        <option value=\"permit\">Permit</option>\n" +
            "                        <option value=\"forbid\">Forbid</option>\n" +
            "                    </select>\n" +
            "                </div>\n" +
            "                <div class=\"form-group\">\n" +
            "                    <label for=\"policy-content\">Cedar Policy:</label>\n" +
            "                    <textarea id=\"policy-content\" placeholder=\"permit(principal, action, resource) when { ... };\">permit(\n" +
            "  principal: User,\n" +
            "  action == Action::\"read\",\n" +
            "  resource: Document\n" +
            ") when {\n" +
            "  principal.clearance >= resource.sensitivity_level &&\n" +
            "  principal.department == resource.department\n" +
            "};</textarea>\n" +
            "                </div>\n" +
            "                <button class=\"button\" onclick=\"createPolicy()\">Create Policy</button>\n" +
            "                <div id=\"policy-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "            </div>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"section\">\n" +
            "            <h2>3. Authorization Testing</h2>\n" +
            "            <div class=\"grid\">\n" +
            "                <div>\n" +
            "                    <div class=\"form-group\">\n" +
            "                        <label for=\"auth-principal\">Principal (User ID):</label>\n" +
            "                        <input type=\"text\" id=\"auth-principal\" placeholder=\"user@company.com\">\n" +
            "                    </div>\n" +
            "                    <div class=\"form-group\">\n" +
            "                        <label for=\"auth-action\">Action:</label>\n" +
            "                        <select id=\"auth-action\">\n" +
            "                            <option value=\"read\">read</option>\n" +
            "                            <option value=\"write\">write</option>\n" +
            "                            <option value=\"delete\">delete</option>\n" +
            "                        </select>\n" +
            "                    </div>\n" +
            "                </div>\n" +
            "                <div>\n" +
            "                    <div class=\"form-group\">\n" +
            "                        <label for=\"auth-resource\">Resource (JSON):</label>\n" +
            "                        <textarea id=\"auth-resource\" placeholder='{ \"id\": \"doc1\", \"classification\": \"confidential\" }'>{\n" +
            "  \"id\": \"financial_report_q4\",\n" +
            "  \"classification\": \"confidential\",\n" +
            "  \"department\": \"finance\",\n" +
            "  \"sensitivity_level\": 3\n" +
            "}</textarea>\n" +
            "                    </div>\n" +
            "                </div>\n" +
            "            </div>\n" +
            "            <button class=\"button\" onclick=\"testAuthorization()\">Test Authorization</button>\n" +
            "            <div id=\"auth-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "        </div>\n" +
            "\n" +
            "        <div class=\"section\">\n" +
            "            <h2>4. Policy Analytics</h2>\n" +
            "            <button class=\"button\" onclick=\"loadAnalytics()\">Load Analytics</button>\n" +
            "            <div id=\"analytics-result\" class=\"result\" style=\"display:none;\"></div>\n" +
            "        </div>\n" +
            "    </div>\n" +
            "\n" +
            "    <script>\n" +
            "        async function createSchema() {\n" +
            "            const result = document.getElementById('schema-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.className = 'result';\n" +
            "            result.innerHTML = 'Creating schema using Cedarling UniFFI...';\n" +
            "            \n" +
            "            try {\n" +
            "                const response = await fetch('/_plugins/_cedarling/data-policies/schema', {\n" +
            "                    method: 'POST',\n" +
            "                    headers: { 'Content-Type': 'application/json' },\n" +
            "                    body: JSON.stringify({\n" +
            "                        name: document.getElementById('schema-name').value,\n" +
            "                        description: document.getElementById('schema-description').value,\n" +
            "                        schema: document.getElementById('schema-content').value\n" +
            "                    })\n" +
            "                });\n" +
            "                \n" +
            "                const data = await response.json();\n" +
            "                result.className = 'result success';\n" +
            "                result.innerHTML = '<strong>Schema Created:</strong><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.className = 'result error';\n" +
            "                result.innerHTML = '<strong>Error:</strong> ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "        \n" +
            "        async function createPolicy() {\n" +
            "            const result = document.getElementById('policy-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.className = 'result';\n" +
            "            result.innerHTML = 'Creating policy using Cedarling UniFFI...';\n" +
            "            \n" +
            "            try {\n" +
            "                const response = await fetch('/_plugins/_cedarling/data-policies/policy', {\n" +
            "                    method: 'POST',\n" +
            "                    headers: { 'Content-Type': 'application/json' },\n" +
            "                    body: JSON.stringify({\n" +
            "                        id: document.getElementById('policy-id').value,\n" +
            "                        description: document.getElementById('policy-description').value,\n" +
            "                        effect: document.getElementById('policy-effect').value,\n" +
            "                        policy: document.getElementById('policy-content').value\n" +
            "                    })\n" +
            "                });\n" +
            "                \n" +
            "                const data = await response.json();\n" +
            "                result.className = 'result success';\n" +
            "                result.innerHTML = '<strong>Policy Created:</strong><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.className = 'result error';\n" +
            "                result.innerHTML = '<strong>Error:</strong> ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "        \n" +
            "        async function testAuthorization() {\n" +
            "            const result = document.getElementById('auth-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.className = 'result';\n" +
            "            result.innerHTML = 'Testing authorization using Cedarling UniFFI...';\n" +
            "            \n" +
            "            try {\n" +
            "                const resourceText = document.getElementById('auth-resource').value;\n" +
            "                const resource = JSON.parse(resourceText);\n" +
            "                \n" +
            "                const response = await fetch('/_plugins/_cedarling/data-policies/authorize', {\n" +
            "                    method: 'POST',\n" +
            "                    headers: { 'Content-Type': 'application/json' },\n" +
            "                    body: JSON.stringify({\n" +
            "                        principal: document.getElementById('auth-principal').value,\n" +
            "                        action: document.getElementById('auth-action').value,\n" +
            "                        resource: resource,\n" +
            "                        context: { access_time: Date.now() }\n" +
            "                    })\n" +
            "                });\n" +
            "                \n" +
            "                const data = await response.json();\n" +
            "                const isAllowed = data.decision === 'ALLOW' || data.allowed === true;\n" +
            "                result.className = isAllowed ? 'result success' : 'result error';\n" +
            "                result.innerHTML = '<strong>Authorization Result:</strong><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.className = 'result error';\n" +
            "                result.innerHTML = '<strong>Error:</strong> ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "        \n" +
            "        async function loadAnalytics() {\n" +
            "            const result = document.getElementById('analytics-result');\n" +
            "            result.style.display = 'block';\n" +
            "            result.className = 'result';\n" +
            "            result.innerHTML = 'Loading policy analytics...';\n" +
            "            \n" +
            "            try {\n" +
            "                const response = await fetch('/_plugins/_cedarling/data-policies/analytics');\n" +
            "                const data = await response.json();\n" +
            "                result.className = 'result success';\n" +
            "                result.innerHTML = '<strong>Policy Analytics:</strong><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';\n" +
            "            } catch (error) {\n" +
            "                result.className = 'result error';\n" +
            "                result.innerHTML = '<strong>Error:</strong> ' + error.message;\n" +
            "            }\n" +
            "        }\n" +
            "    </script>\n" +
            "</body>\n" +
            "</html>";
    }

    // Helper methods
    private Map<String, Object> createPrincipalEntity(String principalId) {
        Map<String, Object> principal = new HashMap<>();
        principal.put("type", "User");
        principal.put("id", principalId);
        return principal;
    }

    private Map<String, Object> createActionEntity(String action) {
        Map<String, Object> actionEntity = new HashMap<>();
        actionEntity.put("type", "Action");
        actionEntity.put("id", action);
        return actionEntity;
    }

    private Map<String, Object> createResourceEntity(Map<String, Object> resource) {
        Map<String, Object> resourceEntity = new HashMap<>();
        resourceEntity.put("type", "Document");
        resourceEntity.putAll(resource);
        return resourceEntity;
    }

    private String generateRequestId() {
        return "req_" + System.currentTimeMillis() + "_" + Math.random();
    }

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