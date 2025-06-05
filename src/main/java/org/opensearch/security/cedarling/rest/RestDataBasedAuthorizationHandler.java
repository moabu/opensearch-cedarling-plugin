package org.opensearch.security.cedarling.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.audit.AuditLogger;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * REST handler for data-based authorization interface
 * 
 * Provides endpoints to authorize access based on actual data content,
 * enabling fine-grained control over document and field access.
 */
public class RestDataBasedAuthorizationHandler extends BaseRestHandler {

    private static final Logger logger = LogManager.getLogger(RestDataBasedAuthorizationHandler.class);
    
    private final CedarlingService cedarlingService;
    private final AuditLogger auditLogger;

    public RestDataBasedAuthorizationHandler(CedarlingService cedarlingService, AuditLogger auditLogger) {
        this.cedarlingService = cedarlingService;
        this.auditLogger = auditLogger;
    }

    @Override
    public String getName() {
        return "cedarling_data_based_authorization_handler";
    }

    @Override
    public List<Route> routes() {
        return Arrays.asList(
            new Route(GET, "/_plugins/_cedarling/data-auth"),
            new Route(POST, "/_plugins/_cedarling/data-auth/authorize"),
            new Route(POST, "/_plugins/_cedarling/data-auth/test"),
            new Route(GET, "/_plugins/_cedarling/data-auth/demo")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            try {
                String path = request.path();
                
                if (path.equals("/_plugins/_cedarling/data-auth")) {
                    handleDataAuthInterface(request, channel);
                } else if (path.equals("/_plugins/_cedarling/data-auth/authorize")) {
                    handleDataAuthorization(request, channel);
                } else if (path.equals("/_plugins/_cedarling/data-auth/test")) {
                    handleDataAuthTest(request, channel);
                } else if (path.equals("/_plugins/_cedarling/data-auth/demo")) {
                    handleDataAuthDemo(request, channel);
                } else {
                    channel.sendResponse(new RestResponse(RestStatus.NOT_FOUND, "Unknown endpoint"));
                }
            } catch (Exception e) {
                logger.error("Error in data-based authorization handler", e);
                channel.sendResponse(new RestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error: " + e.getMessage()));
            }
        };
    }

    private void handleDataAuthInterface(RestRequest request, RestChannel channel) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        
        builder.field("title", "Data-Based Authorization Interface");
        builder.field("description", "Authorize access based on actual data content");
        
        builder.startArray("endpoints");
        builder.startObject()
            .field("path", "/_plugins/_cedarling/data-auth/authorize")
            .field("method", "POST")
            .field("description", "Authorize access to specific data content")
            .endObject();
        builder.startObject()
            .field("path", "/_plugins/_cedarling/data-auth/test")
            .field("method", "POST")
            .field("description", "Test data-based authorization scenarios")
            .endObject();
        builder.startObject()
            .field("path", "/_plugins/_cedarling/data-auth/demo")
            .field("method", "GET")
            .field("description", "Interactive demo of data-based authorization")
            .endObject();
        builder.endArray();
        
        builder.startObject("example_request");
        builder.field("username", "john.doe");
        builder.field("action", "ViewDocument");
        builder.startObject("document_data");
        builder.field("classification", "confidential");
        builder.field("department", "finance");
        builder.field("data_category", "financial_data");
        builder.startObject("content");
        builder.field("title", "Q3 Financial Report");
        builder.field("salary_info", "Contains salary data");
        builder.field("revenue", 1500000);
        builder.endObject();
        builder.endObject();
        builder.endObject();
        
        builder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, builder));
    }

    private void handleDataAuthorization(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> requestBody = parseRequestBody(request);
        
        String username = (String) requestBody.get("username");
        String action = (String) requestBody.getOrDefault("action", "ViewDocument");
        Map<String, Object> documentData = (Map<String, Object>) requestBody.get("document_data");
        Map<String, Object> userContext = (Map<String, Object>) requestBody.getOrDefault("user_context", new HashMap<>());
        
        if (username == null || documentData == null) {
            XContentBuilder errorBuilder = XContentFactory.jsonBuilder();
            errorBuilder.startObject()
                .field("error", "Missing required fields: username and document_data")
                .endObject();
            channel.sendResponse(new RestResponse(RestStatus.BAD_REQUEST, errorBuilder));
            return;
        }

        // Create authorization context from document data
        Map<String, Object> authContext = createAuthorizationContext(documentData, userContext);
        
        // Extract resource information
        String resourceType = "Document";
        String resourceId = documentData.getOrDefault("id", "document").toString();
        
        AuthorizationRequest authRequest = AuthorizationRequest.builder()
            .principal("User", username)
            .action(action)
            .resource(resourceType, resourceId)
            .context(authContext)
            .build();

        long startTime = System.currentTimeMillis();
        
        cedarlingService.authorize(authRequest)
            .whenComplete((authResponse, throwable) -> {
                long processingTime = System.currentTimeMillis() - startTime;
                
                try {
                    if (throwable != null) {
                        logger.error("Data authorization failed", throwable);
                        XContentBuilder errorBuilder = XContentFactory.jsonBuilder();
                        errorBuilder.startObject()
                            .field("error", "Authorization failed: " + throwable.getMessage())
                            .endObject();
                        channel.sendResponse(new RestResponse(RestStatus.INTERNAL_SERVER_ERROR, errorBuilder));
                        return;
                    }

                    // Log authorization decision
                    if (auditLogger != null) {
                        auditLogger.logAuthorizationDecision(authRequest, authResponse, processingTime, "data-auth");
                    }

                    // Build response
                    XContentBuilder responseBuilder = XContentFactory.jsonBuilder();
                    responseBuilder.startObject();
                    
                    responseBuilder.field("username", username);
                    responseBuilder.field("action", action);
                    responseBuilder.field("decision", authResponse.isAllowed() ? "ALLOW" : "DENY");
                    responseBuilder.field("processing_time_ms", processingTime);
                    
                    if (authResponse.getMessage() != null) {
                        responseBuilder.field("reason", authResponse.getMessage());
                    }
                    
                    if (authResponse.getPolicyId() != null) {
                        responseBuilder.field("policy_id", authResponse.getPolicyId());
                    }
                    
                    // Include policy advice for field filtering
                    if (authResponse.getPolicies() != null) {
                        responseBuilder.field("policies", authResponse.getPolicies());
                    }
                    
                    // Data-specific authorization details
                    responseBuilder.startObject("data_analysis");
                    responseBuilder.field("classification", documentData.get("classification"));
                    responseBuilder.field("data_category", documentData.get("data_category"));
                    responseBuilder.field("department", documentData.get("department"));
                    responseBuilder.field("sensitivity_level", documentData.get("sensitivity_level"));
                    responseBuilder.endObject();
                    
                    // Field-level access analysis
                    if (authResponse.isAllowed() && documentData.containsKey("content")) {
                        Map<String, Object> fieldAnalysis = analyzeFieldAccess(
                            username, (Map<String, Object>) documentData.get("content"), authResponse
                        );
                        responseBuilder.field("field_access", fieldAnalysis);
                    }
                    
                    responseBuilder.endObject();
                    
                    channel.sendResponse(new RestResponse(RestStatus.OK, responseBuilder));

                } catch (IOException e) {
                    logger.error("Error building authorization response", e);
                }
            });
    }

    private void handleDataAuthTest(RestRequest request, RestChannel channel) throws IOException {
        // Generate test scenarios for different data types and user roles
        List<Map<String, Object>> testScenarios = generateTestScenarios();
        
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        
        builder.field("test_description", "Data-based authorization test scenarios");
        builder.field("total_scenarios", testScenarios.size());
        
        builder.startArray("scenarios");
        for (Map<String, Object> scenario : testScenarios) {
            builder.startObject();
            builder.field("scenario_name", scenario.get("name"));
            builder.field("username", scenario.get("username"));
            builder.field("user_role", scenario.get("user_role"));
            builder.field("data_classification", scenario.get("data_classification"));
            builder.field("expected_result", scenario.get("expected_result"));
            builder.field("test_description", scenario.get("description"));
            builder.endObject();
        }
        builder.endArray();
        
        builder.field("test_endpoint", "POST /_plugins/_cedarling/data-auth/authorize");
        builder.startObject("example_test_request");
        builder.field("username", "finance_manager");
        builder.field("action", "ViewDocument");
        builder.startObject("document_data");
        builder.field("classification", "confidential");
        builder.field("department", "finance");
        builder.field("data_category", "financial_data");
        builder.startObject("content");
        builder.field("budget", 5000000);
        builder.field("revenue", 12000000);
        builder.field("employee_salaries", "sensitive");
        builder.endObject();
        builder.endObject();
        builder.endObject();
        
        builder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, builder));
    }

    private void handleDataAuthDemo(RestRequest request, RestChannel channel) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        
        builder.field("title", "Data-Based Authorization Demo");
        builder.field("description", "Interactive demonstration of Cedar policies applied to actual data content");
        
        // Demo scenarios
        builder.startArray("demo_scenarios");
        
        // Financial data scenario
        builder.startObject();
        builder.field("scenario", "Financial Data Access");
        builder.field("description", "Testing access to financial documents based on user department and clearance");
        builder.startObject("sample_data");
        builder.field("classification", "confidential");
        builder.field("department", "finance");
        builder.field("data_category", "financial_data");
        builder.startObject("content");
        builder.field("quarterly_revenue", 15000000);
        builder.field("employee_costs", 8000000);
        builder.field("profit_margin", 0.47);
        builder.endObject();
        builder.endObject();
        
        builder.startArray("test_users");
        builder.startObject()
            .field("username", "finance_director")
            .field("expected_access", "FULL")
            .field("reason", "Finance department with director role")
            .endObject();
        builder.startObject()
            .field("username", "hr_manager")
            .field("expected_access", "DENIED")
            .field("reason", "Not in finance department")
            .endObject();
        builder.startObject()
            .field("username", "general_employee")
            .field("expected_access", "DENIED")
            .field("reason", "Insufficient clearance level")
            .endObject();
        builder.endArray();
        builder.endObject();
        
        // Personal data scenario
        builder.startObject();
        builder.field("scenario", "Personal Data Protection");
        builder.field("description", "Testing field-level filtering for personal information");
        builder.startObject("sample_data");
        builder.field("classification", "internal");
        builder.field("department", "hr");
        builder.field("data_category", "personal_data");
        builder.startObject("content");
        builder.field("employee_name", "John Doe");
        builder.field("employee_id", "EMP001");
        builder.field("salary", 95000);
        builder.field("ssn", "123-45-6789");
        builder.field("personal_phone", "+1-555-0123");
        builder.field("emergency_contact", "Jane Doe");
        builder.endObject();
        builder.endObject();
        
        builder.startArray("field_filtering_tests");
        builder.startObject()
            .field("username", "hr_director")
            .field("accessible_fields", Arrays.asList("employee_name", "employee_id", "salary", "emergency_contact"))
            .field("restricted_fields", Arrays.asList("ssn", "personal_phone"))
            .endObject();
        builder.startObject()
            .field("username", "department_manager")
            .field("accessible_fields", Arrays.asList("employee_name", "employee_id"))
            .field("restricted_fields", Arrays.asList("salary", "ssn", "personal_phone", "emergency_contact"))
            .endObject();
        builder.endArray();
        builder.endObject();
        
        // Multi-tenant scenario
        builder.startObject();
        builder.field("scenario", "Multi-Tenant Data Isolation");
        builder.field("description", "Testing tenant boundary enforcement");
        builder.startObject("sample_data");
        builder.field("classification", "internal");
        builder.field("tenant", "company_a");
        builder.field("data_category", "business_data");
        builder.startObject("content");
        builder.field("customer_list", "Company A customers");
        builder.field("sales_data", "Company A sales metrics");
        builder.field("strategic_plans", "Company A 2024 strategy");
        builder.endObject();
        builder.endObject();
        
        builder.startArray("tenant_access_tests");
        builder.startObject()
            .field("username", "company_a_user")
            .field("tenant", "company_a")
            .field("expected_access", "FULL")
            .endObject();
        builder.startObject()
            .field("username", "company_b_user")
            .field("tenant", "company_b")
            .field("expected_access", "DENIED")
            .endObject();
        builder.startObject()
            .field("username", "super_admin")
            .field("tenant", "global")
            .field("expected_access", "FULL")
            .endObject();
        builder.endArray();
        builder.endObject();
        
        builder.endArray();
        
        builder.field("usage_instructions", "Use POST /_plugins/_cedarling/data-auth/authorize with the sample data to test each scenario");
        
        builder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, builder));
    }

    private Map<String, Object> createAuthorizationContext(Map<String, Object> documentData, Map<String, Object> userContext) {
        Map<String, Object> context = new HashMap<>();
        
        // Document metadata
        context.put("classification", documentData.get("classification"));
        context.put("department", documentData.get("department"));
        context.put("data_category", documentData.get("data_category"));
        context.put("sensitivity_level", documentData.get("sensitivity_level"));
        context.put("tenant", documentData.get("tenant"));
        
        // Content analysis
        if (documentData.containsKey("content")) {
            Map<String, Object> content = (Map<String, Object>) documentData.get("content");
            context.put("has_financial_data", containsFinancialData(content));
            context.put("has_personal_data", containsPersonalData(content));
            context.put("content_sensitivity", assessContentSensitivity(content));
        }
        
        // User context
        context.putAll(userContext);
        
        // System context
        context.put("timestamp", System.currentTimeMillis());
        context.put("request_type", "data_based_authorization");
        
        return context;
    }

    private boolean containsFinancialData(Map<String, Object> content) {
        for (String key : content.keySet()) {
            String keyLower = key.toLowerCase();
            if (keyLower.contains("salary") || keyLower.contains("revenue") || 
                keyLower.contains("budget") || keyLower.contains("financial") ||
                keyLower.contains("profit") || keyLower.contains("cost")) {
                return true;
            }
        }
        return false;
    }

    private boolean containsPersonalData(Map<String, Object> content) {
        for (String key : content.keySet()) {
            String keyLower = key.toLowerCase();
            if (keyLower.contains("ssn") || keyLower.contains("phone") || 
                keyLower.contains("personal") || keyLower.contains("address") ||
                keyLower.contains("email") || keyLower.contains("emergency")) {
                return true;
            }
        }
        return false;
    }

    private String assessContentSensitivity(Map<String, Object> content) {
        if (containsFinancialData(content) && containsPersonalData(content)) {
            return "critical";
        } else if (containsFinancialData(content) || containsPersonalData(content)) {
            return "high";
        } else {
            return "medium";
        }
    }

    private Map<String, Object> analyzeFieldAccess(String username, Map<String, Object> content, AuthorizationResponse authResponse) {
        Map<String, Object> fieldAnalysis = new HashMap<>();
        
        Set<String> allowedFields = new HashSet<>(content.keySet());
        Set<String> restrictedFields = new HashSet<>();
        
        // Apply field restrictions from policy advice
        if (authResponse.getPolicies() != null && authResponse.getPolicies().containsKey("field_restrictions")) {
            List<String> restrictions = (List<String>) authResponse.getPolicies().get("field_restrictions");
            for (String restrictedField : restrictions) {
                if (allowedFields.remove(restrictedField)) {
                    restrictedFields.add(restrictedField);
                }
            }
        }
        
        fieldAnalysis.put("total_fields", content.size());
        fieldAnalysis.put("allowed_fields", allowedFields);
        fieldAnalysis.put("restricted_fields", restrictedFields);
        fieldAnalysis.put("field_access_rate", (double) allowedFields.size() / content.size());
        
        return fieldAnalysis;
    }

    private List<Map<String, Object>> generateTestScenarios() {
        List<Map<String, Object>> scenarios = new ArrayList<>();
        
        scenarios.add(createTestScenario("Finance Director accessing financial data", 
            "finance_director", "director", "confidential", "ALLOW", 
            "Finance department director should have access to financial data"));
        
        scenarios.add(createTestScenario("HR Manager accessing personal data", 
            "hr_manager", "manager", "internal", "ALLOW", 
            "HR manager should have access to employee personal data"));
        
        scenarios.add(createTestScenario("General employee accessing confidential data", 
            "general_employee", "employee", "confidential", "DENY", 
            "Regular employee should not access confidential classified data"));
        
        scenarios.add(createTestScenario("Cross-department access attempt", 
            "engineering_lead", "lead", "confidential", "DENY", 
            "Engineering lead should not access finance department data"));
        
        scenarios.add(createTestScenario("Admin accessing any data", 
            "system_admin", "admin", "secret", "ALLOW", 
            "System admin should have access to all data classifications"));
        
        return scenarios;
    }

    private Map<String, Object> createTestScenario(String name, String username, String role, 
                                                 String classification, String expectedResult, String description) {
        Map<String, Object> scenario = new HashMap<>();
        scenario.put("name", name);
        scenario.put("username", username);
        scenario.put("user_role", role);
        scenario.put("data_classification", classification);
        scenario.put("expected_result", expectedResult);
        scenario.put("description", description);
        return scenario;
    }

    private Map<String, Object> parseRequestBody(RestRequest request) throws IOException {
        // Simplified JSON parsing - in production, use proper XContent parsing
        try {
            String content = request.content().utf8ToString();
            // Basic JSON parsing implementation
            return new HashMap<>(); // Placeholder - implement proper JSON parsing
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
}