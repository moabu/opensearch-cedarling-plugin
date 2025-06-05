package org.opensearch.security.cedarling.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.model.PolicyStoreStatus;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Service for communicating with Cedarling policy decision point
 * 
 * This service handles:
 * - Authorization requests to Cedarling
 * - Policy store management
 * - Connection health monitoring
 * - Async operations with timeout handling
 */
public class CedarlingService {
    
    private static final Logger logger = LogManager.getLogger(CedarlingService.class);
    
    private final Settings settings;
    private final ThreadPool threadPool;
    private final ObjectMapper objectMapper;
    private final CloseableHttpClient httpClient;
    
    // Authorization result cache for performance optimization
    private final Map<String, AuthorizationResponse> authorizationCache;
    private final long cacheExpirationMs = 300000; // 5 minutes
    
    private volatile String cedarlingEndpoint;
    private volatile String policyStoreId;
    private volatile boolean enabled;
    private volatile int timeoutMs;
    private volatile boolean auditEnabled;
    
    public CedarlingService(Settings settings, ThreadPool threadPool) {
        this.settings = settings;
        this.threadPool = threadPool;
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClients.createDefault();
        this.authorizationCache = new ConcurrentHashMap<>();
        
        // Initialize settings
        updateSettings(settings);
        
        logger.info("Cedarling service initialized with endpoint: {}, policy store: {}", 
                   cedarlingEndpoint, policyStoreId);
    }
    
    public void updateSettings(Settings settings) {
        this.cedarlingEndpoint = CedarlingSecurityPlugin.CEDARLING_ENDPOINT.get(settings);
        this.policyStoreId = CedarlingSecurityPlugin.CEDARLING_POLICY_STORE_ID.get(settings);
        this.enabled = CedarlingSecurityPlugin.CEDARLING_ENABLED.get(settings);
        this.timeoutMs = CedarlingSecurityPlugin.CEDARLING_TIMEOUT_MS.get(settings);
        this.auditEnabled = CedarlingSecurityPlugin.CEDARLING_AUDIT_ENABLED.get(settings);
        
        logger.debug("Updated Cedarling settings - enabled: {}, endpoint: {}", enabled, cedarlingEndpoint);
    }
    
    /**
     * Make authorization request to Cedarling with caching
     */
    public CompletableFuture<AuthorizationResponse> authorize(AuthorizationRequest request) {
        if (!enabled) {
            return CompletableFuture.completedFuture(
                new AuthorizationResponse(false, "Cedarling integration disabled", null)
            );
        }
        
        // Check cache first
        String cacheKey = buildCacheKey(request);
        AuthorizationResponse cachedResponse = authorizationCache.get(cacheKey);
        
        if (cachedResponse != null) {
            logger.debug("Using cached authorization response for key: {}", cacheKey);
            return CompletableFuture.completedFuture(cachedResponse);
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                AuthorizationResponse response = performAuthorizationRequest(request);
                
                // Cache the response if successful
                if (response.isAllowed()) {
                    authorizationCache.put(cacheKey, response);
                }
                
                return response;
            } catch (Exception e) {
                logger.error("Authorization request failed", e);
                return new AuthorizationResponse(false, "Authorization request failed: " + e.getMessage(), null);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC))
        .orTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .exceptionally(throwable -> {
            logger.error("Authorization request timed out or failed", throwable);
            return new AuthorizationResponse(false, "Request timeout or failure", null);
        });
    }
    
    private AuthorizationResponse performAuthorizationRequest(AuthorizationRequest request) throws IOException {
        // Use authentic jans-cedarling AuthZen evaluation endpoint
        String url = cedarlingEndpoint + "/cedarling/evaluation";
        HttpPost httpPost = new HttpPost(url);
        
        // Build AuthZen evaluation request payload matching jans-cedarling format
        ObjectNode payload = objectMapper.createObjectNode();
        
        // Subject (AuthZen format)
        ObjectNode subject = objectMapper.createObjectNode();
        subject.put("type", request.getPrincipalType());
        subject.put("id", request.getPrincipalId());
        
        // Subject properties
        ObjectNode subjectProperties = objectMapper.createObjectNode();
        if (request.getTenant() != null) {
            subjectProperties.put("tenant", request.getTenant());
        }
        if (request.getAccount() != null) {
            subjectProperties.put("account", request.getAccount());
        }
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            subjectProperties.set("roles", objectMapper.valueToTree(request.getRoles()));
        }
        subject.set("properties", subjectProperties);
        
        // Resource (AuthZen format)
        ObjectNode resource = objectMapper.createObjectNode();
        resource.put("type", request.getResourceType());
        resource.put("id", request.getResourceId());
        
        // Resource properties
        ObjectNode resourceProperties = objectMapper.createObjectNode();
        if (request.getResourceTenant() != null) {
            resourceProperties.put("tenant", request.getResourceTenant());
        }
        if (request.getResourceAccount() != null) {
            resourceProperties.put("account", request.getResourceAccount());
        }
        resource.set("properties", resourceProperties);
        
        // Action (AuthZen format)
        ObjectNode action = objectMapper.createObjectNode();
        action.put("name", request.getAction());
        action.set("properties", objectMapper.createObjectNode()); // Empty properties for now
        
        // Context information
        ObjectNode context = objectMapper.createObjectNode();
        if (request.getContext() != null) {
            context.setAll((ObjectNode) objectMapper.valueToTree(request.getContext()));
        }
        
        // Build AuthZen evaluation request
        payload.set("subject", subject);
        payload.set("action", action);
        payload.set("resource", resource);
        payload.set("context", context);
        
        httpPost.setEntity(new StringEntity(payload.toString(), "UTF-8"));
        httpPost.setHeader("Content-Type", "application/json");
        
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            String responseBody = EntityUtils.toString(response.getEntity());
            
            if (response.getStatusLine().getStatusCode() == 200) {
                ObjectNode responseJson = (ObjectNode) objectMapper.readTree(responseBody);
                
                // Parse AuthZen response format from jans-cedarling
                boolean allowed = responseJson.get("decision").asBoolean();
                String reason = allowed ? "Authorized by Cedarling" : "Denied by Cedarling";
                
                // Extract context as diagnostics if present
                Object diagnostics = null;
                if (responseJson.has("context")) {
                    diagnostics = objectMapper.treeToValue(responseJson.get("context"), Object.class);
                }
                
                if (auditEnabled) {
                    logAuthorizationDecision(request, allowed, reason);
                }
                
                return new AuthorizationResponse(allowed, reason, diagnostics);
            } else {
                logger.warn("Cedarling AuthZen evaluation failed with status: {}, body: {}", 
                           response.getStatusLine().getStatusCode(), responseBody);
                return new AuthorizationResponse(false, "Cedarling service error", null);
            }
        }
    }
    
    /**
     * Check Cedarling service health
     */
    public CompletableFuture<Boolean> checkHealth() {
        if (!enabled) {
            return CompletableFuture.completedFuture(false);
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = cedarlingEndpoint + "/health";
                HttpGet httpGet = new HttpGet(url);
                
                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    return response.getStatusLine().getStatusCode() == 200;
                }
            } catch (Exception e) {
                logger.debug("Cedarling health check failed", e);
                return false;
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC))
        .orTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .exceptionally(throwable -> false);
    }
    
    /**
     * Get policy store status
     */
    public CompletableFuture<PolicyStoreStatus> getPolicyStoreStatus() {
        if (!enabled) {
            return CompletableFuture.completedFuture(
                new PolicyStoreStatus(false, "Cedarling integration disabled", 0, null)
            );
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = cedarlingEndpoint + "/policy_store/" + policyStoreId + "/status";
                HttpGet httpGet = new HttpGet(url);
                
                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        ObjectNode responseJson = (ObjectNode) objectMapper.readTree(responseBody);
                        
                        boolean active = responseJson.get("status").asText().equals("active");
                        String message = responseJson.has("message") ? responseJson.get("message").asText() : null;
                        int policyCount = responseJson.has("policies_count") ? responseJson.get("policies_count").asInt() : 0;
                        String lastUpdated = responseJson.has("last_updated") ? responseJson.get("last_updated").asText() : null;
                        
                        return new PolicyStoreStatus(active, message, policyCount, lastUpdated);
                    } else {
                        return new PolicyStoreStatus(false, "Failed to get policy store status", 0, null);
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to get policy store status", e);
                return new PolicyStoreStatus(false, "Error: " + e.getMessage(), 0, null);
            }
        }, threadPool.executor(ThreadPool.Names.GENERIC))
        .orTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .exceptionally(throwable -> new PolicyStoreStatus(false, "Request timeout", 0, null));
    }
    
    private void logAuthorizationDecision(AuthorizationRequest request, boolean allowed, String reason) {
        try {
            ObjectNode auditLog = objectMapper.createObjectNode();
            auditLog.put("timestamp", System.currentTimeMillis());
            auditLog.put("principal", request.getPrincipalType() + ":" + request.getPrincipalId());
            auditLog.put("action", request.getAction());
            auditLog.put("resource", request.getResourceType() + ":" + request.getResourceId());
            auditLog.put("decision", allowed ? "ALLOW" : "DENY");
            auditLog.put("tenant", request.getTenant());
            auditLog.put("account", request.getAccount());
            if (reason != null) {
                auditLog.put("reason", reason);
            }
            
            logger.info("CEDARLING_AUDIT: {}", auditLog.toString());
        } catch (Exception e) {
            logger.warn("Failed to log authorization decision", e);
        }
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public String getEndpoint() {
        return cedarlingEndpoint;
    }
    
    public String getPolicyStoreId() {
        return policyStoreId;
    }
    
    /**
     * Get HTTP client for external access (used by PolicyStoreSynchronizer)
     */
    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }
    
    /**
     * Invalidate authorization cache (called when policies are updated)
     */
    public void invalidateAuthorizationCache() {
        int cacheSize = authorizationCache.size();
        authorizationCache.clear();
        logger.info("Authorization cache invalidated - cleared {} entries", cacheSize);
    }
    
    /**
     * Build cache key for authorization request
     */
    private String buildCacheKey(AuthorizationRequest request) {
        StringBuilder keyBuilder = new StringBuilder();
        keyBuilder.append(request.getPrincipalType()).append(":")
                 .append(request.getPrincipalId()).append(":")
                 .append(request.getAction()).append(":")
                 .append(request.getResourceType()).append(":")
                 .append(request.getResourceId());
        
        if (request.getTenant() != null) {
            keyBuilder.append(":").append(request.getTenant());
        }
        if (request.getAccount() != null) {
            keyBuilder.append(":").append(request.getAccount());
        }
        
        return keyBuilder.toString();
    }
    
    /**
     * Clean expired cache entries
     */
    public void cleanExpiredCacheEntries() {
        // For simplicity, we clear all cache on policy updates
        // In production, you might want to implement TTL-based expiration
        logger.debug("Cache cleanup - current size: {}", authorizationCache.size());
    }
    
    /**
     * Get cache statistics
     */
    public CacheStatistics getCacheStatistics() {
        return new CacheStatistics(
            authorizationCache.size(),
            cacheExpirationMs
        );
    }
    
    /**
     * Cache statistics for monitoring
     */
    public static class CacheStatistics {
        private final int currentSize;
        private final long expirationMs;
        
        public CacheStatistics(int currentSize, long expirationMs) {
            this.currentSize = currentSize;
            this.expirationMs = expirationMs;
        }
        
        public int getCurrentSize() { return currentSize; }
        public long getExpirationMs() { return expirationMs; }
    }
    
    public void close() {
        try {
            httpClient.close();
        } catch (IOException e) {
            logger.warn("Failed to close HTTP client", e);
        }
    }
}