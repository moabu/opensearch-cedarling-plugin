package org.opensearch.security.cedarling.filter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.audit.AuditAnalytics;
import org.opensearch.security.cedarling.audit.AuditLogger;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.tasks.Task;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Security filter that integrates Cedarling authorization with OpenSearch requests
 * 
 * This filter intercepts OpenSearch operations and enforces Cedar policies
 * for fine-grained access control at the index and document level.
 */
public class CedarlingSecurityFilter implements ActionFilter {

    private static final Logger logger = LogManager.getLogger(CedarlingSecurityFilter.class);

    private final CedarlingService cedarlingService;
    private final ThreadContext threadContext;
    private final AuditLogger auditLogger;
    private final AuditAnalytics auditAnalytics;

    // Actions that require authorization
    private static final List<String> PROTECTED_ACTIONS = Arrays.asList(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:data/write/index",
        "indices:data/write/update",
        "indices:data/write/delete",
        "indices:admin/create",
        "indices:admin/delete",
        "indices:admin/mapping/put"
    );

    public CedarlingSecurityFilter(CedarlingService cedarlingService, ThreadContext threadContext, 
                                  AuditLogger auditLogger, AuditAnalytics auditAnalytics) {
        this.cedarlingService = cedarlingService;
        this.threadContext = threadContext;
        this.auditLogger = auditLogger;
        this.auditAnalytics = auditAnalytics;
    }

    @Override
    public int order() {
        // Execute after authentication but before other security filters
        return 100;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
            Task task,
            String action,
            Request request,
            ActionListener<Response> listener,
            ActionFilterChain<Request, Response> chain
    ) {
        
        // Skip authorization if Cedarling is disabled
        if (!cedarlingService.isEnabled()) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Only authorize protected actions
        if (!PROTECTED_ACTIONS.contains(action)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        try {
            AuthorizationRequest authRequest = buildAuthorizationRequest(action, request);
            
            if (authRequest == null) {
                // Unable to build authorization request, proceed without authorization
                logger.debug("Unable to build authorization request for action: {}", action);
                chain.proceed(task, action, request, listener);
                return;
            }

            // Record start time for performance metrics
            long startTime = System.currentTimeMillis();
            
            // Perform authorization check
            cedarlingService.authorize(authRequest)
                .whenComplete((authResponse, throwable) -> {
                    long processingTime = System.currentTimeMillis() - startTime;
                    String nodeId = task.getDescription();
                    
                    if (throwable != null) {
                        logger.error("Authorization check failed for action: {}", action, throwable);
                        
                        // Log error event for audit
                        if (auditLogger != null) {
                            AuthorizationResponse errorResponse = new AuthorizationResponse(
                                false, "Authorization check failed: " + throwable.getMessage(), null
                            );
                            auditLogger.logAuthorizationDecision(authRequest, errorResponse, processingTime, nodeId);
                        }
                        
                        listener.onFailure(new SecurityException("Authorization check failed"));
                        return;
                    }

                    // Log authorization decision for audit and analytics
                    if (auditLogger != null) {
                        auditLogger.logAuthorizationDecision(authRequest, authResponse, processingTime, nodeId);
                    }
                    
                    if (auditAnalytics != null) {
                        auditAnalytics.analyzeAuthorizationEvent(authRequest, authResponse, processingTime);
                    }

                    if (authResponse.isAllowed()) {
                        logger.debug("Authorization granted for action: {}, principal: {}", 
                                   action, authRequest.getPrincipalId());
                        chain.proceed(task, action, request, listener);
                    } else {
                        logger.warn("Authorization denied for action: {}, principal: {}, reason: {}", 
                                  action, authRequest.getPrincipalId(), authResponse.getReason());
                        listener.onFailure(new SecurityException("Access denied: " + authResponse.getReason()));
                    }
                });

        } catch (Exception e) {
            logger.error("Error during authorization check", e);
            listener.onFailure(new SecurityException("Authorization error"));
        }
    }

    private AuthorizationRequest buildAuthorizationRequest(String action, ActionRequest request) {
        try {
            // Extract user information from thread context
            String username = threadContext.getTransient("_user");
            String tenant = threadContext.getTransient("_tenant");
            String account = threadContext.getTransient("_account");
            List<String> roles = (List<String>) threadContext.getTransient("_roles");

            if (username == null) {
                logger.debug("No user information found in thread context");
                return null;
            }

            // Extract resource information based on request type
            String resourceType = "index";
            String resourceId = extractResourceId(request);
            String cedarAction = mapActionToCedarAction(action);

            if (resourceId == null || cedarAction == null) {
                return null;
            }

            // Build context with additional request information
            Map<String, Object> context = new HashMap<>();
            context.put("opensearch_action", action);
            context.put("timestamp", System.currentTimeMillis());
            
            // Add request-specific context
            addRequestContext(request, context);

            return AuthorizationRequest.builder()
                .principal("User", username)
                .action(cedarAction)
                .resource(resourceType, resourceId)
                .tenant(tenant)
                .account(account)
                .roles(roles)
                .context(context)
                .build();

        } catch (Exception e) {
            logger.error("Error building authorization request", e);
            return null;
        }
    }

    private String extractResourceId(ActionRequest request) {
        if (request instanceof SearchRequest) {
            SearchRequest searchRequest = (SearchRequest) request;
            String[] indices = searchRequest.indices();
            return indices != null && indices.length > 0 ? indices[0] : null;
        } else if (request instanceof GetRequest) {
            GetRequest getRequest = (GetRequest) request;
            return getRequest.index();
        } else if (request instanceof IndexRequest) {
            IndexRequest indexRequest = (IndexRequest) request;
            return indexRequest.index();
        } else if (request instanceof UpdateRequest) {
            UpdateRequest updateRequest = (UpdateRequest) request;
            return updateRequest.index();
        } else if (request instanceof DeleteRequest) {
            DeleteRequest deleteRequest = (DeleteRequest) request;
            return deleteRequest.index();
        }
        
        return null;
    }

    private String mapActionToCedarAction(String opensearchAction) {
        switch (opensearchAction) {
            case "indices:data/read/search":
            case "indices:data/read/get":
                return "ViewIndex";
            case "indices:data/write/index":
            case "indices:data/write/update":
                return "WriteIndex";
            case "indices:data/write/delete":
                return "DeleteIndex";
            case "indices:admin/create":
                return "CreateIndex";
            case "indices:admin/delete":
                return "AdministerIndex";
            case "indices:admin/mapping/put":
                return "ConfigureIndex";
            default:
                return null;
        }
    }

    private void addRequestContext(ActionRequest request, Map<String, Object> context) {
        if (request instanceof SearchRequest) {
            SearchRequest searchRequest = (SearchRequest) request;
            context.put("search_type", searchRequest.searchType().toString());
            if (searchRequest.source() != null) {
                context.put("has_query", searchRequest.source().query() != null);
                context.put("size", searchRequest.source().size());
            }
        } else if (request instanceof IndexRequest) {
            IndexRequest indexRequest = (IndexRequest) request;
            context.put("document_id", indexRequest.id());
            context.put("document_type", indexRequest.type());
        } else if (request instanceof GetRequest) {
            GetRequest getRequest = (GetRequest) request;
            context.put("document_id", getRequest.id());
            context.put("document_type", getRequest.type());
        }
    }
}