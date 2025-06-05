package org.opensearch.security.cedarling.demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.service.CedarlingService;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Comprehensive demonstration of post-query Cedar policy enforcement
 * 
 * This demo shows how Cedar policies are applied after OpenSearch returns
 * query results, filtering documents and fields based on content and user permissions.
 */
public class PostQueryEnforcementDemo {
    
    private static final Logger logger = LogManager.getLogger(PostQueryEnforcementDemo.class);
    
    private final CedarlingService cedarlingService;
    
    public PostQueryEnforcementDemo(CedarlingService cedarlingService) {
        this.cedarlingService = cedarlingService;
    }
    
    /**
     * Demonstrate document-level filtering based on content
     */
    public CompletableFuture<Map<String, Object>> demonstrateDocumentFiltering(
            String username, 
            List<Map<String, Object>> queryResults
    ) {
        logger.info("Starting post-query document filtering demo for user: {}", username);
        
        List<CompletableFuture<Map<String, Object>>> evaluations = new ArrayList<>();
        
        for (Map<String, Object> document : queryResults) {
            CompletableFuture<Map<String, Object>> evaluation = evaluateDocumentAccess(
                username, document
            );
            evaluations.add(evaluation);
        }
        
        return CompletableFuture.allOf(evaluations.toArray(new CompletableFuture[0]))
            .thenApply(result -> {
                List<Map<String, Object>> allowedDocuments = evaluations.stream()
                    .map(CompletableFuture::join)
                    .filter(Objects::nonNull)
                    .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
                
                Map<String, Object> filteringResult = new HashMap<>();
                filteringResult.put("original_count", queryResults.size());
                filteringResult.put("allowed_count", allowedDocuments.size());
                filteringResult.put("filtered_count", queryResults.size() - allowedDocuments.size());
                filteringResult.put("allowed_documents", allowedDocuments);
                filteringResult.put("filtering_rate", 
                    ((double) (queryResults.size() - allowedDocuments.size()) / queryResults.size()) * 100);
                
                logger.info("Document filtering completed: {}/{} documents allowed", 
                           allowedDocuments.size(), queryResults.size());
                
                return filteringResult;
            });
    }
    
    /**
     * Demonstrate field-level filtering within documents
     */
    public CompletableFuture<Map<String, Object>> demonstrateFieldFiltering(
            String username,
            Map<String, Object> document
    ) {
        logger.info("Starting field-level filtering demo for document: {}", 
                   document.get("_id"));
        
        // Create authorization request for field access
        Map<String, Object> context = new HashMap<>();
        context.put("document_source", document.get("_source"));
        context.put("document_classification", getDocumentClassification(document));
        context.put("user_clearance", getUserClearanceLevel(username));
        
        AuthorizationRequest request = AuthorizationRequest.builder()
            .principal("User", username)
            .action("ViewDocumentFields")
            .resource("Document", document.get("_index") + "/" + document.get("_id"))
            .context(context)
            .build();
        
        return cedarlingService.authorize(request)
            .thenApply(response -> applyFieldLevelPolicies(document, response, username));
    }
    
    /**
     * Demonstrate content-based access control
     */
    public CompletableFuture<Map<String, Object>> demonstrateContentBasedFiltering(
            String username,
            List<Map<String, Object>> documents
    ) {
        logger.info("Starting content-based filtering demo for {} documents", documents.size());
        
        Map<String, List<Map<String, Object>>> categorizedResults = new HashMap<>();
        categorizedResults.put("financial_data", new ArrayList<>());
        categorizedResults.put("personal_data", new ArrayList<>());
        categorizedResults.put("public_data", new ArrayList<>());
        categorizedResults.put("restricted_data", new ArrayList<>());
        
        List<CompletableFuture<Void>> evaluations = new ArrayList<>();
        
        for (Map<String, Object> document : documents) {
            CompletableFuture<Void> evaluation = evaluateContentBasedAccess(
                username, document, categorizedResults
            );
            evaluations.add(evaluation);
        }
        
        return CompletableFuture.allOf(evaluations.toArray(new CompletableFuture[0]))
            .thenApply(result -> {
                Map<String, Object> contentFilteringResult = new HashMap<>();
                contentFilteringResult.put("total_documents", documents.size());
                contentFilteringResult.put("categorized_results", categorizedResults);
                
                // Calculate access statistics
                int totalAllowed = categorizedResults.values().stream()
                    .mapToInt(List::size)
                    .sum();
                
                contentFilteringResult.put("total_allowed", totalAllowed);
                contentFilteringResult.put("total_filtered", documents.size() - totalAllowed);
                contentFilteringResult.put("access_rate", 
                    ((double) totalAllowed / documents.size()) * 100);
                
                logger.info("Content-based filtering completed: {}/{} documents accessible", 
                           totalAllowed, documents.size());
                
                return contentFilteringResult;
            });
    }
    
    /**
     * Demonstrate multi-tenant data isolation
     */
    public CompletableFuture<Map<String, Object>> demonstrateMultiTenantFiltering(
            String username,
            String tenant,
            List<Map<String, Object>> documents
    ) {
        logger.info("Starting multi-tenant filtering demo for user: {} in tenant: {}", 
                   username, tenant);
        
        List<CompletableFuture<Map<String, Object>>> tenantEvaluations = new ArrayList<>();
        
        for (Map<String, Object> document : documents) {
            CompletableFuture<Map<String, Object>> evaluation = evaluateTenantAccess(
                username, tenant, document
            );
            tenantEvaluations.add(evaluation);
        }
        
        return CompletableFuture.allOf(tenantEvaluations.toArray(new CompletableFuture[0]))
            .thenApply(result -> {
                List<Map<String, Object>> tenantAccessibleDocs = tenantEvaluations.stream()
                    .map(CompletableFuture::join)
                    .filter(Objects::nonNull)
                    .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
                
                Map<String, Object> tenantResult = new HashMap<>();
                tenantResult.put("tenant", tenant);
                tenantResult.put("user", username);
                tenantResult.put("total_documents", documents.size());
                tenantResult.put("tenant_accessible", tenantAccessibleDocs.size());
                tenantResult.put("tenant_filtered", documents.size() - tenantAccessibleDocs.size());
                tenantResult.put("accessible_documents", tenantAccessibleDocs);
                tenantResult.put("isolation_effectiveness", 
                    ((double) (documents.size() - tenantAccessibleDocs.size()) / documents.size()) * 100);
                
                logger.info("Multi-tenant filtering completed: {}/{} documents accessible in tenant {}", 
                           tenantAccessibleDocs.size(), documents.size(), tenant);
                
                return tenantResult;
            });
    }
    
    private CompletableFuture<Map<String, Object>> evaluateDocumentAccess(
            String username, 
            Map<String, Object> document
    ) {
        Map<String, Object> context = createDocumentContext(document);
        
        AuthorizationRequest request = AuthorizationRequest.builder()
            .principal("User", username)
            .action("ViewDocument")
            .resource("Document", document.get("_index") + "/" + document.get("_id"))
            .context(context)
            .build();
        
        return cedarlingService.authorize(request)
            .thenApply(response -> response.isAllowed() ? document : null);
    }
    
    private CompletableFuture<Void> evaluateContentBasedAccess(
            String username,
            Map<String, Object> document,
            Map<String, List<Map<String, Object>>> categorizedResults
    ) {
        String dataCategory = determineDataCategory(document);
        
        Map<String, Object> context = createDocumentContext(document);
        context.put("data_category", dataCategory);
        
        AuthorizationRequest request = AuthorizationRequest.builder()
            .principal("User", username)
            .action("AccessCategory")
            .resource("DataCategory", dataCategory)
            .context(context)
            .build();
        
        return cedarlingService.authorize(request)
            .thenAccept(response -> {
                if (response.isAllowed()) {
                    synchronized (categorizedResults) {
                        categorizedResults.computeIfAbsent(dataCategory, k -> new ArrayList<>())
                                        .add(document);
                    }
                }
            });
    }
    
    private CompletableFuture<Map<String, Object>> evaluateTenantAccess(
            String username,
            String tenant,
            Map<String, Object> document
    ) {
        Map<String, Object> context = createDocumentContext(document);
        context.put("requesting_tenant", tenant);
        context.put("document_tenant", document.get("_tenant"));
        
        AuthorizationRequest request = AuthorizationRequest.builder()
            .principal("User", username)
            .action("AccessTenantData")
            .resource("TenantDocument", tenant + "/" + document.get("_id"))
            .tenant(tenant)
            .context(context)
            .build();
        
        return cedarlingService.authorize(request)
            .thenApply(response -> response.isAllowed() ? document : null);
    }
    
    private Map<String, Object> applyFieldLevelPolicies(
            Map<String, Object> document,
            AuthorizationResponse response,
            String username
    ) {
        Map<String, Object> filteredDocument = new HashMap<>(document);
        
        if (response.getPolicies() != null && response.getPolicies().containsKey("restricted_fields")) {
            @SuppressWarnings("unchecked")
            List<String> restrictedFields = (List<String>) response.getPolicies().get("restricted_fields");
            
            @SuppressWarnings("unchecked")
            Map<String, Object> source = new HashMap<>((Map<String, Object>) document.get("_source"));
            
            for (String restrictedField : restrictedFields) {
                removeNestedField(source, restrictedField);
            }
            
            filteredDocument.put("_source", source);
            filteredDocument.put("_field_filtering_applied", true);
            filteredDocument.put("_restricted_fields_count", restrictedFields.size());
        }
        
        return filteredDocument;
    }
    
    private void removeNestedField(Map<String, Object> source, String fieldPath) {
        String[] parts = fieldPath.split("\\.");
        if (parts.length == 1) {
            source.remove(fieldPath);
        } else {
            Object nested = source.get(parts[0]);
            if (nested instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) nested;
                String remainingPath = fieldPath.substring(parts[0].length() + 1);
                removeNestedField(nestedMap, remainingPath);
            }
        }
    }
    
    private Map<String, Object> createDocumentContext(Map<String, Object> document) {
        Map<String, Object> context = new HashMap<>();
        context.put("document_id", document.get("_id"));
        context.put("document_index", document.get("_index"));
        context.put("document_type", document.get("_type"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> source = (Map<String, Object>) document.get("_source");
        if (source != null) {
            context.put("classification", source.get("classification"));
            context.put("department", source.get("department"));
            context.put("sensitivity_level", source.get("sensitivity_level"));
            context.put("data_category", source.get("data_category"));
            context.put("tenant", source.get("tenant"));
        }
        
        return context;
    }
    
    private String getDocumentClassification(Map<String, Object> document) {
        @SuppressWarnings("unchecked")
        Map<String, Object> source = (Map<String, Object>) document.get("_source");
        return source != null ? (String) source.get("classification") : "unclassified";
    }
    
    private String getUserClearanceLevel(String username) {
        // In a real implementation, this would fetch from user directory
        Map<String, String> userClearances = Map.of(
            "admin", "secret",
            "manager", "confidential",
            "employee", "internal",
            "guest", "public"
        );
        return userClearances.getOrDefault(username, "public");
    }
    
    private String determineDataCategory(Map<String, Object> document) {
        @SuppressWarnings("unchecked")
        Map<String, Object> source = (Map<String, Object>) document.get("_source");
        if (source == null) return "public_data";
        
        String category = (String) source.get("data_category");
        if (category != null) return category;
        
        // Infer category from content
        String content = source.toString().toLowerCase();
        if (content.contains("salary") || content.contains("financial") || content.contains("revenue")) {
            return "financial_data";
        } else if (content.contains("personal") || content.contains("email") || content.contains("phone")) {
            return "personal_data";
        } else if (content.contains("classified") || content.contains("confidential")) {
            return "restricted_data";
        } else {
            return "public_data";
        }
    }
    
    /**
     * Generate comprehensive demo report
     */
    public Map<String, Object> generateDemoReport(
            Map<String, Object> documentFiltering,
            Map<String, Object> fieldFiltering,
            Map<String, Object> contentFiltering,
            Map<String, Object> tenantFiltering
    ) {
        Map<String, Object> report = new HashMap<>();
        report.put("timestamp", System.currentTimeMillis());
        report.put("demo_type", "post_query_cedar_enforcement");
        
        report.put("document_level_filtering", documentFiltering);
        report.put("field_level_filtering", fieldFiltering);
        report.put("content_based_filtering", contentFiltering);
        report.put("multi_tenant_filtering", tenantFiltering);
        
        // Calculate overall effectiveness
        int totalDocuments = (Integer) documentFiltering.get("original_count");
        int totalAllowed = (Integer) documentFiltering.get("allowed_count");
        double overallEffectiveness = ((double) (totalDocuments - totalAllowed) / totalDocuments) * 100;
        
        report.put("overall_filtering_effectiveness", overallEffectiveness);
        report.put("cedar_engine_status", "operational");
        report.put("post_query_enforcement", "active");
        
        logger.info("Post-query Cedar enforcement demo completed successfully");
        logger.info("Overall filtering effectiveness: {:.2f}%", overallEffectiveness);
        
        return report;
    }
}