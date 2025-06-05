package org.opensearch.security.cedarling.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Comprehensive audit logging for Cedarling security decisions
 * 
 * Features:
 * - Structured JSON audit logs
 * - Performance metrics tracking
 * - Security event categorization
 * - Configurable log levels and formats
 * - Async logging for performance
 */
public class AuditLogger {
    
    private static final Logger logger = LogManager.getLogger("cedarling.audit");
    private static final Logger metricsLogger = LogManager.getLogger("cedarling.metrics");
    
    private final Settings settings;
    private final ThreadPool threadPool;
    private final ObjectMapper objectMapper;
    
    // Audit configuration
    private volatile boolean auditEnabled;
    private volatile boolean metricsEnabled;
    private volatile boolean includeRequestDetails;
    private volatile boolean includePolicyDetails;
    private volatile String auditLogLevel;
    
    // Performance metrics
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong allowedRequests = new AtomicLong(0);
    private final AtomicLong deniedRequests = new AtomicLong(0);
    private final AtomicLong errorRequests = new AtomicLong(0);
    private final Map<String, AtomicLong> actionMetrics = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> tenantMetrics = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> userMetrics = new ConcurrentHashMap<>();
    
    public AuditLogger(Settings settings, ThreadPool threadPool) {
        this.settings = settings;
        this.threadPool = threadPool;
        this.objectMapper = new ObjectMapper();
        
        updateSettings(settings);
        
        logger.info("Cedarling audit logger initialized - enabled: {}, metrics: {}", 
                   auditEnabled, metricsEnabled);
    }
    
    public void updateSettings(Settings settings) {
        this.auditEnabled = CedarlingSecurityPlugin.CEDARLING_AUDIT_ENABLED.get(settings);
        this.metricsEnabled = settings.getAsBoolean("cedarling.audit.metrics.enabled", true);
        this.includeRequestDetails = settings.getAsBoolean("cedarling.audit.include_request_details", true);
        this.includePolicyDetails = settings.getAsBoolean("cedarling.audit.include_policy_details", false);
        this.auditLogLevel = settings.get("cedarling.audit.log_level", "INFO");
        
        logger.debug("Audit settings updated - enabled: {}, level: {}", auditEnabled, auditLogLevel);
    }
    
    /**
     * Log authorization decision with full context
     */
    public void logAuthorizationDecision(
            AuthorizationRequest request,
            AuthorizationResponse response,
            long processingTimeMs,
            String nodeId
    ) {
        if (!auditEnabled) {
            return;
        }
        
        // Update metrics
        updateMetrics(request, response);
        
        // Log asynchronously for performance
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode auditEntry = createAuditEntry(request, response, processingTimeMs, nodeId);
                String auditJson = objectMapper.writeValueAsString(auditEntry);
                
                // Log based on decision and configuration
                if (response.isAllowed()) {
                    logWithLevel("Authorization ALLOWED: " + auditJson);
                } else {
                    logWithLevel("Authorization DENIED: " + auditJson);
                }
                
            } catch (Exception e) {
                logger.error("Failed to log audit entry", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log security events (policy sync, errors, etc.)
     */
    public void logSecurityEvent(SecurityEventType eventType, String description, Map<String, Object> context) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode eventEntry = objectMapper.createObjectNode();
                eventEntry.put("timestamp", getCurrentTimestamp());
                eventEntry.put("event_type", eventType.name());
                eventEntry.put("event_category", "security");
                eventEntry.put("description", description);
                eventEntry.put("severity", eventType.getSeverity());
                
                if (context != null && !context.isEmpty()) {
                    ObjectNode contextNode = objectMapper.valueToTree(context);
                    eventEntry.set("context", contextNode);
                }
                
                String eventJson = objectMapper.writeValueAsString(eventEntry);
                logWithLevel("Security Event: " + eventJson);
                
            } catch (Exception e) {
                logger.error("Failed to log security event", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log policy synchronization events
     */
    public void logPolicySyncEvent(String action, boolean success, String details, int policyCount) {
        Map<String, Object> context = Map.of(
            "action", action,
            "success", success,
            "policy_count", policyCount,
            "details", details
        );
        
        SecurityEventType eventType = success ? 
            SecurityEventType.POLICY_SYNC_SUCCESS : 
            SecurityEventType.POLICY_SYNC_FAILURE;
            
        logSecurityEvent(eventType, "Policy synchronization " + action, context);
    }
    
    /**
     * Log post-query Cedar policy enforcement events
     */
    public void logPostQueryEnforcement(Map<String, Object> enforcementData) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode eventEntry = objectMapper.createObjectNode();
                eventEntry.put("timestamp", getCurrentTimestamp());
                eventEntry.put("event_type", "POST_QUERY_ENFORCEMENT");
                eventEntry.put("event_category", "security");
                eventEntry.put("description", "Cedar policy enforcement applied to query results");
                eventEntry.put("severity", "INFO");
                
                // Add enforcement metrics
                eventEntry.put("username", (String) enforcementData.get("username"));
                eventEntry.put("total_documents", (Integer) enforcementData.get("total_documents"));
                eventEntry.put("allowed_documents", (Integer) enforcementData.get("allowed_documents"));
                eventEntry.put("filtered_documents", (Integer) enforcementData.get("filtered_documents"));
                eventEntry.put("processing_time_ms", (Long) enforcementData.get("processing_time_ms"));
                eventEntry.put("enforcement_type", (String) enforcementData.get("enforcement_type"));
                
                // Calculate filtering efficiency
                int total = (Integer) enforcementData.get("total_documents");
                int allowed = (Integer) enforcementData.get("allowed_documents");
                if (total > 0) {
                    double filteringRate = ((double) (total - allowed) / total) * 100;
                    eventEntry.put("filtering_rate_percent", filteringRate);
                }
                
                String eventJson = objectMapper.writeValueAsString(eventEntry);
                logWithLevel("Post-Query Enforcement: " + eventJson);
                
            } catch (Exception e) {
                logger.error("Failed to log post-query enforcement event", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Generate performance and security metrics report
     */
    public AuditMetrics getMetrics() {
        return new AuditMetrics(
            totalRequests.get(),
            allowedRequests.get(),
            deniedRequests.get(),
            errorRequests.get(),
            Map.copyOf(actionMetrics.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey,
                    e -> e.getValue().get()
                ))),
            Map.copyOf(tenantMetrics.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey,
                    e -> e.getValue().get()
                ))),
            Map.copyOf(userMetrics.entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey,
                    e -> e.getValue().get()
                )))
        );
    }
    
    /**
     * Log periodic metrics summary
     */
    public void logMetricsSummary() {
        if (!metricsEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                AuditMetrics metrics = getMetrics();
                ObjectNode metricsNode = objectMapper.createObjectNode();
                
                metricsNode.put("timestamp", getCurrentTimestamp());
                metricsNode.put("total_requests", metrics.getTotalRequests());
                metricsNode.put("allowed_requests", metrics.getAllowedRequests());
                metricsNode.put("denied_requests", metrics.getDeniedRequests());
                metricsNode.put("error_requests", metrics.getErrorRequests());
                
                // Calculate rates
                long total = metrics.getTotalRequests();
                if (total > 0) {
                    metricsNode.put("allow_rate", (double) metrics.getAllowedRequests() / total);
                    metricsNode.put("deny_rate", (double) metrics.getDeniedRequests() / total);
                    metricsNode.put("error_rate", (double) metrics.getErrorRequests() / total);
                }
                
                // Top actions and tenants
                metricsNode.set("top_actions", objectMapper.valueToTree(metrics.getActionMetrics()));
                metricsNode.set("top_tenants", objectMapper.valueToTree(metrics.getTenantMetrics()));
                
                String metricsJson = objectMapper.writeValueAsString(metricsNode);
                metricsLogger.info("Cedarling Metrics Summary: {}", metricsJson);
                
            } catch (Exception e) {
                logger.error("Failed to log metrics summary", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    private ObjectNode createAuditEntry(
            AuthorizationRequest request,
            AuthorizationResponse response,
            long processingTimeMs,
            String nodeId
    ) {
        ObjectNode entry = objectMapper.createObjectNode();
        
        // Core audit fields
        entry.put("timestamp", getCurrentTimestamp());
        entry.put("decision", response.isAllowed() ? "ALLOW" : "DENY");
        entry.put("processing_time_ms", processingTimeMs);
        entry.put("node_id", nodeId);
        entry.put("request_id", generateRequestId());
        
        // Principal information
        ObjectNode principal = objectMapper.createObjectNode();
        principal.put("type", request.getPrincipalType());
        principal.put("id", request.getPrincipalId());
        if (request.getTenant() != null) {
            principal.put("tenant", request.getTenant());
        }
        if (request.getAccount() != null) {
            principal.put("account", request.getAccount());
        }
        entry.set("principal", principal);
        
        // Resource information
        ObjectNode resource = objectMapper.createObjectNode();
        resource.put("type", request.getResourceType());
        resource.put("id", request.getResourceId());
        entry.set("resource", resource);
        
        // Action
        entry.put("action", request.getAction());
        
        // Response details
        if (response.getMessage() != null) {
            entry.put("message", response.getMessage());
        }
        if (response.getPolicyId() != null && includePolicyDetails) {
            entry.put("policy_id", response.getPolicyId());
        }
        
        // Request details (if enabled)
        if (includeRequestDetails && request.getContext() != null) {
            entry.set("context", objectMapper.valueToTree(request.getContext()));
        }
        
        return entry;
    }
    
    /**
     * Log data-based authorization decisions
     */
    public void logDataBasedAuthorization(String principal, String action, Map<String, Object> resource, Map<String, Object> result) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("event_type", "data_based_authorization");
                entry.put("timestamp", getCurrentTimestamp());
                entry.put("principal", principal);
                entry.put("action", action);
                entry.set("resource", objectMapper.valueToTree(resource));
                entry.set("result", objectMapper.valueToTree(result));
                entry.put("authorization_method", "cedarling_uniffi");
                
                logger.info("Data-based authorization: {}", entry.toString());
            } catch (Exception e) {
                logger.error("Failed to log data-based authorization", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log schema operations
     */
    public void logSchemaOperation(String operation, String schemaName, Map<String, Object> result) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("event_type", "schema_operation");
                entry.put("timestamp", getCurrentTimestamp());
                entry.put("operation", operation);
                entry.put("schema_name", schemaName);
                entry.set("result", objectMapper.valueToTree(result));
                entry.put("schema_engine", "cedarling_uniffi");
                
                logger.info("Schema operation: {}", entry.toString());
            } catch (Exception e) {
                logger.error("Failed to log schema operation", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log policy operations
     */
    public void logPolicyOperation(String operation, String policyId, Map<String, Object> result) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("event_type", "policy_operation");
                entry.put("timestamp", getCurrentTimestamp());
                entry.put("operation", operation);
                entry.put("policy_id", policyId);
                entry.set("result", objectMapper.valueToTree(result));
                entry.put("policy_engine", "cedarling_uniffi");
                
                logger.info("Policy operation: {}", entry.toString());
            } catch (Exception e) {
                logger.error("Failed to log policy operation", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log TBAC evaluation results
     */
    public void logTBACEvaluation(String action, String userId, Object evaluationResult) {
        if (!auditEnabled) {
            return;
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("event_type", "tbac_evaluation");
                entry.put("timestamp", getCurrentTimestamp());
                entry.put("action", action);
                entry.put("user_id", userId);
                entry.set("evaluation_result", objectMapper.valueToTree(evaluationResult));
                entry.put("evaluation_method", "tbac_ext_object");
                
                logger.info("TBAC evaluation: {}", entry.toString());
            } catch (Exception e) {
                logger.error("Failed to log TBAC evaluation", e);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    /**
     * Log general errors
     */
    public void logError(String message, Exception e) {
        CompletableFuture.runAsync(() -> {
            try {
                ObjectNode entry = objectMapper.createObjectNode();
                entry.put("event_type", "error");
                entry.put("timestamp", getCurrentTimestamp());
                entry.put("message", message);
                entry.put("error_class", e.getClass().getSimpleName());
                entry.put("error_message", e.getMessage());
                
                logger.error("Error event: {}", entry.toString());
            } catch (Exception logError) {
                logger.error("Failed to log error", logError);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    private void updateMetrics(AuthorizationRequest request, AuthorizationResponse response) {
        if (!metricsEnabled) {
            return;
        }
        
        totalRequests.incrementAndGet();
        
        if (response.isAllowed()) {
            allowedRequests.incrementAndGet();
        } else {
            deniedRequests.incrementAndGet();
        }
        
        // Track by action
        actionMetrics.computeIfAbsent(request.getAction(), k -> new AtomicLong(0))
                   .incrementAndGet();
        
        // Track by tenant
        if (request.getTenant() != null) {
            tenantMetrics.computeIfAbsent(request.getTenant(), k -> new AtomicLong(0))
                        .incrementAndGet();
        }
        
        // Track by user
        userMetrics.computeIfAbsent(request.getPrincipalId(), k -> new AtomicLong(0))
                  .incrementAndGet();
    }
    
    private void logWithLevel(String message) {
        switch (auditLogLevel.toUpperCase()) {
            case "DEBUG":
                logger.debug(message);
                break;
            case "WARN":
                logger.warn(message);
                break;
            case "ERROR":
                logger.error(message);
                break;
            default:
                logger.info(message);
        }
    }
    
    private String getCurrentTimestamp() {
        return Instant.now().atOffset(ZoneOffset.UTC)
                     .format(DateTimeFormatter.ISO_INSTANT);
    }
    
    private String generateRequestId() {
        return "audit-" + System.currentTimeMillis() + "-" + 
               Thread.currentThread().getId();
    }
    
    /**
     * Reset metrics counters
     */
    public void resetMetrics() {
        totalRequests.set(0);
        allowedRequests.set(0);
        deniedRequests.set(0);
        errorRequests.set(0);
        actionMetrics.clear();
        tenantMetrics.clear();
        userMetrics.clear();
        
        logger.info("Cedarling audit metrics reset");
    }
    
    public boolean isAuditEnabled() {
        return auditEnabled;
    }
    
    public boolean isMetricsEnabled() {
        return metricsEnabled;
    }
}