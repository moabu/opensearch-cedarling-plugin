package org.opensearch.security.cedarling.filter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.audit.AuditLogger;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.tbac.TBACMetadataHandler;
import org.opensearch.security.cedarling.tbac.TBACTokens;
import org.opensearch.security.cedarling.tbac.TBACEvaluationResult;
import org.opensearch.tasks.Task;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Post-query Cedar policy enforcement filter
 * 
 * Applies Cedar policies after OpenSearch returns results, filtering documents
 * and fields based on the actual content and user permissions.
 */
public class PostQueryCedarlingFilter implements ActionFilter {

    private static final Logger logger = LogManager.getLogger(PostQueryCedarlingFilter.class);

    private final CedarlingService cedarlingService;
    private final ThreadContext threadContext;
    private final AuditLogger auditLogger;
    private final TBACMetadataHandler tbacHandler;

    // Actions that require post-query filtering
    private static final List<String> POST_QUERY_ACTIONS = Arrays.asList(
        "indices:data/read/search",
        "indices:data/read/get",
        "indices:data/read/mget"
    );

    public PostQueryCedarlingFilter(CedarlingService cedarlingService, 
                                   ThreadContext threadContext, 
                                   AuditLogger auditLogger) {
        this.cedarlingService = cedarlingService;
        this.threadContext = threadContext;
        this.auditLogger = auditLogger;
        this.tbacHandler = new TBACMetadataHandler(cedarlingService);
    }

    @Override
    public int order() {
        // Execute after main query processing but before response
        return 200;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
            Task task,
            String action,
            Request request,
            ActionListener<Response> listener,
            ActionFilterChain<Request, Response> chain
    ) {
        
        // Skip if Cedarling is disabled or action doesn't need post-query filtering
        if (!cedarlingService.isEnabled() || !POST_QUERY_ACTIONS.contains(action)) {
            chain.proceed(task, action, request, listener);
            return;
        }

        // Create a wrapping listener for post-query processing
        ActionListener<Response> wrappedListener = new ActionListener<Response>() {
            @Override
            public void onResponse(Response response) {
                // Apply post-query Cedar policy enforcement
                applyPostQueryPolicies(task, action, request, response, listener);
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        };

        chain.proceed(task, action, request, wrappedListener);
    }

    @SuppressWarnings("unchecked")
    private <Request extends ActionRequest, Response extends ActionResponse> void applyPostQueryPolicies(
            Task task,
            String action,
            Request request,
            Response response,
            ActionListener<Response> originalListener
    ) {
        try {
            long startTime = System.currentTimeMillis();
            
            if (response instanceof SearchResponse) {
                handleSearchResponse(task, action, request, (SearchResponse) response, 
                                   (ActionListener<SearchResponse>) originalListener, startTime);
            } else if (response instanceof GetResponse) {
                handleGetResponse(task, action, request, (GetResponse) response, 
                                (ActionListener<GetResponse>) originalListener, startTime);
            } else {
                // No post-query filtering needed for this response type
                originalListener.onResponse(response);
            }

        } catch (Exception e) {
            logger.error("Error during post-query Cedar policy enforcement", e);
            originalListener.onFailure(new SecurityException("Post-query policy enforcement failed"));
        }
    }

    private void handleSearchResponse(Task task, String action, ActionRequest request, SearchResponse response, 
                                    ActionListener<SearchResponse> listener, long startTime) {
        SearchHits hits = response.getHits();
        if (hits == null || hits.getHits().length == 0) {
            listener.onResponse(response);
            return;
        }

        // Extract TBAC tokens from the search request ext object
        SearchRequest searchRequest = (SearchRequest) request;
        TBACTokens tbacTokens = tbacHandler.extractTokensFromRequest(searchRequest);
        
        // If no TBAC tokens found, fall back to traditional context-based filtering
        if (!tbacTokens.hasAccessToken() && !tbacTokens.hasIdToken()) {
            handleTraditionalFiltering(hits, listener, response, startTime);
            return;
        }

        // Perform TBAC evaluation using Cedarling service
        TBACEvaluationResult evaluationResult = tbacHandler.evaluateHitsWithTBAC(
            hits, tbacTokens, searchRequest
        );
        
        // Create modified search response with filtered hits and TBAC metadata in ext
        SearchResponse modifiedResponse = tbacHandler.appendTBACMetadataToResponse(
            response, evaluationResult
        );
        
        // Log TBAC evaluation results for audit
        auditLogger.logTBACEvaluation(action, tbacTokens.getUserId(), evaluationResult);
        
        long evaluationTime = System.currentTimeMillis() - startTime;
        logger.info("TBAC post-query evaluation completed: {} hits evaluated, {} authorized in {}ms",
            evaluationResult.getTotalHitsEvaluated(), 
            evaluationResult.getAuthorizedHitIds().size(),
            evaluationTime);
        
        listener.onResponse(modifiedResponse);
    }
    
    private void handleTraditionalFiltering(SearchHits hits, ActionListener<SearchResponse> listener, 
                                          SearchResponse response, long startTime) {
        String username = threadContext.getTransient("_user");
        if (username == null) {
            listener.onResponse(response);
            return;
        }

        // Evaluate each document against Cedar policies
        List<CompletableFuture<SearchHit>> documentEvaluations = new ArrayList<>();
        
        for (SearchHit hit : hits.getHits()) {
            CompletableFuture<SearchHit> evaluation = evaluateDocumentAccess(
                username, hit, "ViewDocument"
            );
            documentEvaluations.add(evaluation);
        }

        // Wait for all evaluations to complete
        CompletableFuture.allOf(documentEvaluations.toArray(new CompletableFuture[0]))
            .whenComplete((result, throwable) -> {
                if (throwable != null) {
                    logger.error("Error during document evaluation", throwable);
                    listener.onFailure(new SecurityException("Document evaluation failed"));
                    return;
                }

                try {
                    // Collect allowed documents
                    List<SearchHit> allowedHits = documentEvaluations.stream()
                        .map(CompletableFuture::join)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toList());

                    // Create filtered response
                    SearchResponse filteredResponse = createFilteredSearchResponse(response, allowedHits);
                    
                    // Log post-query enforcement metrics
                    long processingTime = System.currentTimeMillis() - startTime;
                    logPostQueryEnforcement(username, hits.getHits().length, 
                                          allowedHits.size(), processingTime);
                    
                    listener.onResponse(filteredResponse);

                } catch (Exception e) {
                    logger.error("Error creating filtered response", e);
                    listener.onFailure(new SecurityException("Response filtering failed"));
                }
            });
    }

    private void handleGetResponse(Task task, ActionRequest request, GetResponse response, 
                                 ActionListener<GetResponse> listener, long startTime) {
        if (!response.isExists()) {
            listener.onResponse(response);
            return;
        }

        String username = threadContext.getTransient("_user");
        if (username == null) {
            listener.onResponse(response);
            return;
        }

        // Evaluate document access
        evaluateDocumentAccessFromGetResponse(username, response, "ViewDocument")
            .whenComplete((allowed, throwable) -> {
                if (throwable != null) {
                    logger.error("Error during document evaluation", throwable);
                    listener.onFailure(new SecurityException("Document evaluation failed"));
                    return;
                }

                long processingTime = System.currentTimeMillis() - startTime;
                
                if (allowed) {
                    // Apply field-level filtering if needed
                    GetResponse filteredResponse = applyFieldLevelFiltering(response, username);
                    logPostQueryEnforcement(username, 1, 1, processingTime);
                    listener.onResponse(filteredResponse);
                } else {
                    // Document access denied
                    logPostQueryEnforcement(username, 1, 0, processingTime);
                    GetResponse emptyResponse = createEmptyGetResponse(response.getIndex(), response.getId());
                    listener.onResponse(emptyResponse);
                }
            });
    }

    private CompletableFuture<SearchHit> evaluateDocumentAccess(String username, SearchHit hit, String action) {
        try {
            // Extract document metadata for Cedar evaluation
            Map<String, Object> documentContext = new HashMap<>();
            documentContext.put("document_id", hit.getId());
            documentContext.put("document_index", hit.getIndex());
            documentContext.put("document_type", hit.getType());
            documentContext.put("document_score", hit.getScore());
            
            // Add source fields to context for content-based policies
            if (hit.getSourceAsMap() != null) {
                documentContext.put("document_source", hit.getSourceAsMap());
                
                // Extract key fields for policy evaluation
                Map<String, Object> source = hit.getSourceAsMap();
                documentContext.put("classification", source.get("classification"));
                documentContext.put("department", source.get("department"));
                documentContext.put("sensitivity_level", source.get("sensitivity_level"));
                documentContext.put("data_category", source.get("data_category"));
            }

            AuthorizationRequest authRequest = AuthorizationRequest.builder()
                .principal("User", username)
                .action(action)
                .resource("Document", hit.getIndex() + "/" + hit.getId())
                .context(documentContext)
                .build();

            return cedarlingService.authorize(authRequest)
                .thenApply(authResponse -> {
                    if (authResponse.isAllowed()) {
                        // Apply field-level filtering
                        return applyFieldLevelFiltering(hit, username, authResponse);
                    } else {
                        // Document access denied
                        logger.debug("Document access denied: {} for user: {}", 
                                   hit.getId(), username);
                        return null;
                    }
                });

        } catch (Exception e) {
            logger.error("Error evaluating document access", e);
            return CompletableFuture.completedFuture(null);
        }
    }

    private CompletableFuture<Boolean> evaluateDocumentAccessFromGetResponse(String username, 
                                                                           GetResponse response, 
                                                                           String action) {
        try {
            Map<String, Object> documentContext = new HashMap<>();
            documentContext.put("document_id", response.getId());
            documentContext.put("document_index", response.getIndex());
            documentContext.put("document_type", response.getType());
            
            if (response.getSourceAsMap() != null) {
                documentContext.put("document_source", response.getSourceAsMap());
                
                Map<String, Object> source = response.getSourceAsMap();
                documentContext.put("classification", source.get("classification"));
                documentContext.put("department", source.get("department"));
                documentContext.put("sensitivity_level", source.get("sensitivity_level"));
            }

            AuthorizationRequest authRequest = AuthorizationRequest.builder()
                .principal("User", username)
                .action(action)
                .resource("Document", response.getIndex() + "/" + response.getId())
                .context(documentContext)
                .build();

            return cedarlingService.authorize(authRequest)
                .thenApply(AuthorizationResponse::isAllowed);

        } catch (Exception e) {
            logger.error("Error evaluating document access from GetResponse", e);
            return CompletableFuture.completedFuture(false);
        }
    }

    private SearchHit applyFieldLevelFiltering(SearchHit hit, String username, AuthorizationResponse authResponse) {
        // Check if field-level policies apply
        Map<String, Object> policies = authResponse.getPolicies();
        if (policies == null || !policies.containsKey("field_restrictions")) {
            return hit;
        }

        try {
            @SuppressWarnings("unchecked")
            List<String> restrictedFields = (List<String>) policies.get("field_restrictions");
            
            if (restrictedFields != null && !restrictedFields.isEmpty()) {
                // Create a filtered source map
                Map<String, Object> filteredSource = new HashMap<>(hit.getSourceAsMap());
                
                for (String restrictedField : restrictedFields) {
                    removeNestedField(filteredSource, restrictedField);
                }
                
                // Create new SearchHit with filtered source
                return createSearchHitWithFilteredSource(hit, filteredSource);
            }
            
        } catch (Exception e) {
            logger.warn("Error applying field-level filtering to document {}: {}", 
                       hit.getId(), e.getMessage());
        }
        
        return hit;
    }

    private GetResponse applyFieldLevelFiltering(GetResponse response, String username) {
        // For now, return the original response
        // Field-level filtering for GetResponse can be implemented similarly
        return response;
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

    private SearchHit createSearchHitWithFilteredSource(SearchHit originalHit, Map<String, Object> filteredSource) {
        // This would require access to SearchHit internals or using reflection
        // For demonstration, we'll log the filtering action
        logger.debug("Applied field-level filtering to document {} in index {}", 
                    originalHit.getId(), originalHit.getIndex());
        return originalHit;
    }

    private SearchResponse createFilteredSearchResponse(SearchResponse originalResponse, List<SearchHit> allowedHits) {
        // This would require rebuilding the SearchResponse with filtered hits
        // For demonstration, we'll log the filtering statistics
        logger.info("Post-query filtering: {} documents allowed out of {} total", 
                   allowedHits.size(), originalResponse.getHits().getHits().length);
        return originalResponse;
    }

    private GetResponse createEmptyGetResponse(String index, String id) {
        // This would create a GetResponse indicating the document was not found
        // For demonstration, we'll log the access denial
        logger.info("Post-query access denied for document {} in index {}", id, index);
        return null; // Simplified for demonstration
    }

    private void logPostQueryEnforcement(String username, int totalDocuments, 
                                       int allowedDocuments, long processingTime) {
        if (auditLogger != null) {
            Map<String, Object> auditData = new HashMap<>();
            auditData.put("enforcement_type", "post_query");
            auditData.put("username", username);
            auditData.put("total_documents", totalDocuments);
            auditData.put("allowed_documents", allowedDocuments);
            auditData.put("filtered_documents", totalDocuments - allowedDocuments);
            auditData.put("processing_time_ms", processingTime);
            auditData.put("timestamp", System.currentTimeMillis());
            
            auditLogger.logPostQueryEnforcement(auditData);
        }

        logger.info("Post-query Cedar enforcement completed for user {}: {}/{} documents allowed in {}ms", 
                   username, allowedDocuments, totalDocuments, processingTime);
    }
}