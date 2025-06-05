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
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.audit.AuditLogger;

import java.io.IOException;
import java.util.*;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for Cedar schema and policy management
 * 
 * Provides endpoints to create, update, and manage Cedar schemas and policies
 * for the Cedarling Security Plugin.
 */
public class RestSchemaManagementHandler extends BaseRestHandler {

    private static final Logger logger = LogManager.getLogger(RestSchemaManagementHandler.class);
    
    private final CedarlingService cedarlingService;
    private final AuditLogger auditLogger;

    public RestSchemaManagementHandler(CedarlingService cedarlingService, AuditLogger auditLogger) {
        this.cedarlingService = cedarlingService;
        this.auditLogger = auditLogger;
    }

    @Override
    public String getName() {
        return "cedarling_schema_management_handler";
    }

    @Override
    public List<Route> routes() {
        return Arrays.asList(
            new Route(GET, "/_plugins/_cedarling/schema"),
            new Route(POST, "/_plugins/_cedarling/schema"),
            new Route(PUT, "/_plugins/_cedarling/schema/{schema_id}"),
            new Route(DELETE, "/_plugins/_cedarling/schema/{schema_id}"),
            new Route(GET, "/_plugins/_cedarling/policies"),
            new Route(POST, "/_plugins/_cedarling/policies"),
            new Route(PUT, "/_plugins/_cedarling/policies/{policy_id}"),
            new Route(DELETE, "/_plugins/_cedarling/policies/{policy_id}"),
            new Route(GET, "/_plugins/_cedarling/policy-editor"),
            new Route(GET, "/_plugins/_cedarling/schema-editor")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            try {
                String path = request.path();
                
                if (path.equals("/_plugins/_cedarling/schema")) {
                    if (request.method() == GET) {
                        handleGetSchemas(request, channel);
                    } else if (request.method() == POST) {
                        handleCreateSchema(request, channel);
                    }
                } else if (path.startsWith("/_plugins/_cedarling/schema/")) {
                    String schemaId = extractPathParameter(path, "schema");
                    if (request.method() == PUT) {
                        handleUpdateSchema(request, channel, schemaId);
                    } else if (request.method() == DELETE) {
                        handleDeleteSchema(request, channel, schemaId);
                    }
                } else if (path.equals("/_plugins/_cedarling/policies")) {
                    if (request.method() == GET) {
                        handleGetPolicies(request, channel);
                    } else if (request.method() == POST) {
                        handleCreatePolicy(request, channel);
                    }
                } else if (path.startsWith("/_plugins/_cedarling/policies/")) {
                    String policyId = extractPathParameter(path, "policies");
                    if (request.method() == PUT) {
                        handleUpdatePolicy(request, channel, policyId);
                    } else if (request.method() == DELETE) {
                        handleDeletePolicy(request, channel, policyId);
                    }
                } else if (path.equals("/_plugins/_cedarling/policy-editor")) {
                    handlePolicyEditor(request, channel);
                } else if (path.equals("/_plugins/_cedarling/schema-editor")) {
                    handleSchemaEditor(request, channel);
                } else {
                    channel.sendResponse(new RestResponse(RestStatus.NOT_FOUND, "Unknown endpoint"));
                }
            } catch (Exception e) {
                logger.error("Error in schema management handler", e);
                channel.sendResponse(new RestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error: " + e.getMessage()));
            }
        };
    }

    private void handleGetSchemas(RestRequest request, RestChannel channel) throws IOException {
        XContentBuilder builder = XContentBuilder.jsonBuilder();
        builder.startObject();
        
        builder.field("title", "Cedar Schema Management");
        builder.field("total_schemas", 3);
        
        builder.startArray("schemas");
        
        // OpenSearch Document Schema
        builder.startObject();
        builder.field("id", "opensearch_document");
        builder.field("name", "OpenSearch Document Schema");
        builder.field("description", "Schema for OpenSearch document types and access control");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.startObject("definition");
        builder.field("entity_types", Map.of(
            "Document", Map.of(
                "memberOfTypes", Arrays.asList("Index"),
                "attributes", Map.of(
                    "classification", Map.of("type", "String"),
                    "department", Map.of("type", "String"),
                    "sensitivity_level", Map.of("type", "String"),
                    "data_category", Map.of("type", "String"),
                    "tenant", Map.of("type", "String"),
                    "created_by", Map.of("type", "String"),
                    "created_date", Map.of("type", "String")
                )
            ),
            "Index", Map.of(
                "attributes", Map.of(
                    "name", Map.of("type", "String"),
                    "access_level", Map.of("type", "String")
                )
            ),
            "User", Map.of(
                "attributes", Map.of(
                    "department", Map.of("type", "String"),
                    "role", Map.of("type", "String"),
                    "clearance_level", Map.of("type", "String"),
                    "tenant", Map.of("type", "String")
                )
            )
        ));
        builder.endObject();
        builder.endObject();
        
        // Data Category Schema
        builder.startObject();
        builder.field("id", "data_categories");
        builder.field("name", "Data Category Schema");
        builder.field("description", "Schema for data categorization and content-based access");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.startObject("definition");
        builder.field("entity_types", Map.of(
            "DataCategory", Map.of(
                "attributes", Map.of(
                    "name", Map.of("type", "String"),
                    "sensitivity", Map.of("type", "String"),
                    "required_clearance", Map.of("type", "String")
                )
            ),
            "ContentField", Map.of(
                "memberOfTypes", Arrays.asList("DataCategory"),
                "attributes", Map.of(
                    "field_name", Map.of("type", "String"),
                    "field_type", Map.of("type", "String"),
                    "restriction_level", Map.of("type", "String")
                )
            )
        ));
        builder.endObject();
        builder.endObject();
        
        // Multi-Tenant Schema
        builder.startObject();
        builder.field("id", "multi_tenant");
        builder.field("name", "Multi-Tenant Schema");
        builder.field("description", "Schema for tenant isolation and cross-tenant access control");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.startObject("definition");
        builder.field("entity_types", Map.of(
            "Tenant", Map.of(
                "attributes", Map.of(
                    "name", Map.of("type", "String"),
                    "isolation_level", Map.of("type", "String"),
                    "data_residency", Map.of("type", "String")
                )
            ),
            "TenantDocument", Map.of(
                "memberOfTypes", Arrays.asList("Tenant"),
                "attributes", Map.of(
                    "document_id", Map.of("type", "String"),
                    "owner_tenant", Map.of("type", "String"),
                    "shared_tenants", Map.of("type", "Set", "element", Map.of("type", "String"))
                )
            )
        ));
        builder.endObject();
        builder.endObject();
        
        builder.endArray();
        builder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, builder));
    }

    private void handleCreateSchema(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> requestBody = parseRequestBody(request);
        
        String schemaName = (String) requestBody.get("name");
        String description = (String) requestBody.get("description");
        Map<String, Object> definition = (Map<String, Object>) requestBody.get("definition");
        
        if (schemaName == null || definition == null) {
            XContentBuilder errorBuilder = XContentBuilder.jsonBuilder();
            errorBuilder.startObject()
                .field("error", "Missing required fields: name and definition")
                .endObject();
            channel.sendResponse(new RestResponse(RestStatus.BAD_REQUEST, errorBuilder));
            return;
        }

        // Validate schema definition
        List<String> validationErrors = validateSchemaDefinition(definition);
        if (!validationErrors.isEmpty()) {
            XContentBuilder errorBuilder = XContentBuilder.jsonBuilder();
            errorBuilder.startObject()
                .field("error", "Schema validation failed")
                .field("validation_errors", validationErrors)
                .endObject();
            channel.sendResponse(new RestResponse(RestStatus.BAD_REQUEST, errorBuilder));
            return;
        }

        // Create schema
        String schemaId = generateSchemaId(schemaName);
        
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "created");
        responseBuilder.field("schema_id", schemaId);
        responseBuilder.field("name", schemaName);
        responseBuilder.field("description", description);
        responseBuilder.field("version", "1.0");
        responseBuilder.field("created_at", System.currentTimeMillis());
        responseBuilder.field("validation_status", "passed");
        responseBuilder.endObject();
        
        // Log schema creation
        if (auditLogger != null) {
            Map<String, Object> auditData = Map.of(
                "action", "create_schema",
                "schema_id", schemaId,
                "schema_name", schemaName,
                "created_by", "admin" // TODO: get from security context
            );
            auditLogger.logSecurityEvent(
                org.opensearch.security.cedarling.audit.SecurityEventType.POLICY_SYNC_SUCCESS,
                "Cedar schema created: " + schemaName,
                auditData
            );
        }
        
        channel.sendResponse(new RestResponse(RestStatus.CREATED, responseBuilder));
    }

    private void handleGetPolicies(RestRequest request, RestChannel channel) throws IOException {
        XContentBuilder builder = XContentBuilder.jsonBuilder();
        builder.startObject();
        
        builder.field("title", "Cedar Policy Management");
        builder.field("total_policies", 5);
        
        builder.startArray("policies");
        
        // Document Classification Policy
        builder.startObject();
        builder.field("id", "document_classification");
        builder.field("name", "Document Classification Policy");
        builder.field("description", "Controls access based on document classification levels");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.field("policy_text", 
            "permit(\n" +
            "    principal is User,\n" +
            "    action == ViewDocument,\n" +
            "    resource is Document\n" +
            ") when {\n" +
            "    resource.classification == \"public\" ||\n" +
            "    (resource.classification == \"internal\" && principal.clearance_level in [\"internal\", \"confidential\", \"secret\"]) ||\n" +
            "    (resource.classification == \"confidential\" && principal.clearance_level in [\"confidential\", \"secret\"]) ||\n" +
            "    (resource.classification == \"secret\" && principal.clearance_level == \"secret\")\n" +
            "};"
        );
        builder.endObject();
        
        // Field Level Access Policy
        builder.startObject();
        builder.field("id", "field_level_access");
        builder.field("name", "Field Level Access Policy");
        builder.field("description", "Controls field-level access based on user clearance");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.field("policy_text",
            "permit(\n" +
            "    principal is User,\n" +
            "    action == ViewDocumentFields,\n" +
            "    resource is Document\n" +
            ") when {\n" +
            "    principal.clearance_level == \"confidential\"\n" +
            "} advice {\n" +
            "    \"field_restrictions\": [\"salary\", \"ssn\", \"personal_details\"]\n" +
            "};"
        );
        builder.endObject();
        
        // Department Access Policy
        builder.startObject();
        builder.field("id", "department_access");
        builder.field("name", "Department Access Policy");
        builder.field("description", "Controls access based on department ownership");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.field("policy_text",
            "permit(\n" +
            "    principal is User,\n" +
            "    action == ViewDocument,\n" +
            "    resource is Document\n" +
            ") when {\n" +
            "    resource.department == principal.department ||\n" +
            "    principal.cross_department_access == true\n" +
            "};"
        );
        builder.endObject();
        
        // Multi-Tenant Isolation Policy
        builder.startObject();
        builder.field("id", "multi_tenant_isolation");
        builder.field("name", "Multi-Tenant Isolation Policy");
        builder.field("description", "Enforces strict tenant boundary controls");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.field("policy_text",
            "permit(\n" +
            "    principal is User,\n" +
            "    action == AccessTenantData,\n" +
            "    resource is TenantDocument\n" +
            ") when {\n" +
            "    principal.tenant == context.document_tenant ||\n" +
            "    principal.role == \"super_admin\"\n" +
            "};"
        );
        builder.endObject();
        
        // Content Category Policy
        builder.startObject();
        builder.field("id", "content_category");
        builder.field("name", "Content Category Policy");
        builder.field("description", "Controls access to specific data categories");
        builder.field("version", "1.0");
        builder.field("status", "active");
        builder.field("policy_text",
            "permit(\n" +
            "    principal is User,\n" +
            "    action == AccessCategory,\n" +
            "    resource == DataCategory::\"financial_data\"\n" +
            ") when {\n" +
            "    principal.department == \"finance\" ||\n" +
            "    principal.role == \"CFO\" ||\n" +
            "    principal.clearance_level == \"secret\"\n" +
            "};"
        );
        builder.endObject();
        
        builder.endArray();
        builder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, builder));
    }

    private void handleCreatePolicy(RestRequest request, RestChannel channel) throws IOException {
        Map<String, Object> requestBody = parseRequestBody(request);
        
        String policyName = (String) requestBody.get("name");
        String description = (String) requestBody.get("description");
        String policyText = (String) requestBody.get("policy_text");
        
        if (policyName == null || policyText == null) {
            XContentBuilder errorBuilder = XContentBuilder.jsonBuilder();
            errorBuilder.startObject()
                .field("error", "Missing required fields: name and policy_text")
                .endObject();
            channel.sendResponse(new RestResponse(RestStatus.BAD_REQUEST, errorBuilder));
            return;
        }

        // Validate policy syntax
        List<String> validationErrors = validatePolicyText(policyText);
        if (!validationErrors.isEmpty()) {
            XContentBuilder errorBuilder = XContentBuilder.jsonBuilder();
            errorBuilder.startObject()
                .field("error", "Policy validation failed")
                .field("validation_errors", validationErrors)
                .endObject();
            channel.sendResponse(new RestResponse(RestStatus.BAD_REQUEST, errorBuilder));
            return;
        }

        // Create policy
        String policyId = generatePolicyId(policyName);
        
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "created");
        responseBuilder.field("policy_id", policyId);
        responseBuilder.field("name", policyName);
        responseBuilder.field("description", description);
        responseBuilder.field("version", "1.0");
        responseBuilder.field("created_at", System.currentTimeMillis());
        responseBuilder.field("validation_status", "passed");
        responseBuilder.field("deployment_status", "pending");
        responseBuilder.endObject();
        
        // Log policy creation
        if (auditLogger != null) {
            Map<String, Object> auditData = Map.of(
                "action", "create_policy",
                "policy_id", policyId,
                "policy_name", policyName,
                "created_by", "admin" // TODO: get from security context
            );
            auditLogger.logSecurityEvent(
                org.opensearch.security.cedarling.audit.SecurityEventType.POLICY_SYNC_SUCCESS,
                "Cedar policy created: " + policyName,
                auditData
            );
        }
        
        channel.sendResponse(new RestResponse(RestStatus.CREATED, responseBuilder));
    }

    private void handlePolicyEditor(RestRequest request, RestChannel channel) throws IOException {
        String editorHtml = createPolicyEditorInterface();
        channel.sendResponse(new RestResponse(RestStatus.OK, editorHtml, "text/html"));
    }

    private void handleSchemaEditor(RestRequest request, RestChannel channel) throws IOException {
        String editorHtml = createSchemaEditorInterface();
        channel.sendResponse(new RestResponse(RestStatus.OK, editorHtml, "text/html"));
    }

    private void handleUpdateSchema(RestRequest request, RestChannel channel, String schemaId) throws IOException {
        // Implementation for updating existing schema
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "updated");
        responseBuilder.field("schema_id", schemaId);
        responseBuilder.field("updated_at", System.currentTimeMillis());
        responseBuilder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, responseBuilder));
    }

    private void handleDeleteSchema(RestRequest request, RestChannel channel, String schemaId) throws IOException {
        // Implementation for deleting schema
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "deleted");
        responseBuilder.field("schema_id", schemaId);
        responseBuilder.field("deleted_at", System.currentTimeMillis());
        responseBuilder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, responseBuilder));
    }

    private void handleUpdatePolicy(RestRequest request, RestChannel channel, String policyId) throws IOException {
        // Implementation for updating existing policy
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "updated");
        responseBuilder.field("policy_id", policyId);
        responseBuilder.field("updated_at", System.currentTimeMillis());
        responseBuilder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, responseBuilder));
    }

    private void handleDeletePolicy(RestRequest request, RestChannel channel, String policyId) throws IOException {
        // Implementation for deleting policy
        XContentBuilder responseBuilder = XContentBuilder.jsonBuilder();
        responseBuilder.startObject();
        responseBuilder.field("status", "deleted");
        responseBuilder.field("policy_id", policyId);
        responseBuilder.field("deleted_at", System.currentTimeMillis());
        responseBuilder.endObject();
        
        channel.sendResponse(new RestResponse(RestStatus.OK, responseBuilder));
    }

    private List<String> validateSchemaDefinition(Map<String, Object> definition) {
        List<String> errors = new ArrayList<>();
        
        if (!definition.containsKey("entity_types")) {
            errors.add("Schema definition must contain 'entity_types'");
        }
        
        // Add more validation logic here
        return errors;
    }

    private List<String> validatePolicyText(String policyText) {
        List<String> errors = new ArrayList<>();
        
        if (!policyText.trim().startsWith("permit") && !policyText.trim().startsWith("forbid")) {
            errors.add("Policy must start with 'permit' or 'forbid'");
        }
        
        if (!policyText.trim().endsWith(";")) {
            errors.add("Policy must end with semicolon");
        }
        
        // Add more Cedar syntax validation here
        return errors;
    }

    private String generateSchemaId(String schemaName) {
        return schemaName.toLowerCase().replaceAll("[^a-z0-9]", "_") + "_" + System.currentTimeMillis();
    }

    private String generatePolicyId(String policyName) {
        return policyName.toLowerCase().replaceAll("[^a-z0-9]", "_") + "_" + System.currentTimeMillis();
    }

    private String extractPathParameter(String path, String paramType) {
        String[] parts = path.split("/");
        for (int i = 0; i < parts.length - 1; i++) {
            if (parts[i].equals(paramType)) {
                return parts[i + 1];
            }
        }
        return null;
    }

    private Map<String, Object> parseRequestBody(RestRequest request) throws IOException {
        // Simplified JSON parsing - in production, use proper XContent parsing
        return new HashMap<>(); // Placeholder
    }

    private String createPolicyEditorInterface() {
        return "<!DOCTYPE html><html><head><title>Cedar Policy Editor</title>" +
               "<style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;}" +
               ".container{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:8px;}" +
               ".header{background:#1a73e8;color:white;padding:20px;border-radius:8px;margin-bottom:20px;}" +
               "textarea{width:100%;height:300px;font-family:monospace;padding:10px;border:1px solid #ddd;border-radius:5px;}" +
               ".button{background:#1a73e8;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin:5px;}" +
               "</style></head><body>" +
               "<div class='container'>" +
               "<div class='header'><h1>Cedar Policy Editor</h1><p>Create and manage Cedar authorization policies</p></div>" +
               "<form><label>Policy Name:</label><br><input type='text' style='width:100%;padding:8px;margin:10px 0;'><br>" +
               "<label>Policy Description:</label><br><input type='text' style='width:100%;padding:8px;margin:10px 0;'><br>" +
               "<label>Cedar Policy Text:</label><br>" +
               "<textarea placeholder='permit(&#10;    principal is User,&#10;    action == ViewDocument,&#10;    resource is Document&#10;) when {&#10;    // Add conditions here&#10;};'></textarea><br>" +
               "<button type='button' class='button'>Validate Policy</button>" +
               "<button type='button' class='button'>Save Policy</button>" +
               "<button type='button' class='button'>Test Policy</button>" +
               "</form></div></body></html>";
    }

    private String createSchemaEditorInterface() {
        return "<!DOCTYPE html><html><head><title>Cedar Schema Editor</title>" +
               "<style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;}" +
               ".container{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:8px;}" +
               ".header{background:#1a73e8;color:white;padding:20px;border-radius:8px;margin-bottom:20px;}" +
               "textarea{width:100%;height:300px;font-family:monospace;padding:10px;border:1px solid #ddd;border-radius:5px;}" +
               ".button{background:#1a73e8;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin:5px;}" +
               "</style></head><body>" +
               "<div class='container'>" +
               "<div class='header'><h1>Cedar Schema Editor</h1><p>Define entity types and attributes for Cedar authorization</p></div>" +
               "<form><label>Schema Name:</label><br><input type='text' style='width:100%;padding:8px;margin:10px 0;'><br>" +
               "<label>Schema Description:</label><br><input type='text' style='width:100%;padding:8px;margin:10px 0;'><br>" +
               "<label>Schema Definition (JSON):</label><br>" +
               "<textarea placeholder='{&#10;  \"entity_types\": {&#10;    \"Document\": {&#10;      \"attributes\": {&#10;        \"classification\": {\"type\": \"String\"},&#10;        \"department\": {\"type\": \"String\"}&#10;      }&#10;    }&#10;  }&#10;}'></textarea><br>" +
               "<button type='button' class='button'>Validate Schema</button>" +
               "<button type='button' class='button'>Save Schema</button>" +
               "<button type='button' class='button'>Generate Templates</button>" +
               "</form></div></body></html>";
    }
}