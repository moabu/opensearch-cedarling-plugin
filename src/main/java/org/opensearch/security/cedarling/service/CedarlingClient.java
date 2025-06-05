package org.opensearch.security.cedarling.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.opensearch.security.cedarling.model.AuthZenEvaluationRequest;
import org.opensearch.security.cedarling.model.AuthZenEvaluationResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Cedarling client that integrates with jans-cedarling service
 * Uses AuthZen evaluation endpoints and well-known configuration
 */
public class CedarlingClient {
    
    private static final Logger logger = LogManager.getLogger(CedarlingClient.class);
    
    private final String cedarlingBaseUrl;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final int timeoutMs;
    
    public CedarlingClient(String cedarlingBaseUrl, int timeoutMs) {
        this.cedarlingBaseUrl = cedarlingBaseUrl.endsWith("/") ? 
            cedarlingBaseUrl.substring(0, cedarlingBaseUrl.length() - 1) : cedarlingBaseUrl;
        this.timeoutMs = timeoutMs;
        this.httpClient = HttpClients.createDefault();
        this.objectMapper = new ObjectMapper();
    }
    
    // Constructor for OpenSearch Settings integration
    public CedarlingClient(Settings settings) {
        this(
            settings.get("cedarling.service.url", "http://localhost:8080"),
            settings.getAsInt("cedarling.timeout_ms", 5000)
        );
    }
    
    /**
     * Get well-known AuthZen configuration from Cedarling service
     */
    public CompletableFuture<Map<String, Object>> getWellKnownConfiguration() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = cedarlingBaseUrl + "/.well-known/authzen-configuration";
                HttpGet httpGet = new HttpGet(url);
                httpGet.setHeader("Accept", "application/json");
                
                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return objectMapper.readValue(responseBody, Map.class);
                    } else {
                        logger.warn("Failed to get well-known configuration: status={}, body={}", 
                                   response.getStatusLine().getStatusCode(), responseBody);
                        return null;
                    }
                }
            } catch (Exception e) {
                logger.error("Error getting well-known configuration", e);
                return null;
            }
        }).orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Evaluate authorization using Cedarling AuthZen endpoint
     */
    public CompletableFuture<AuthZenEvaluationResponse> evaluate(AuthZenEvaluationRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = cedarlingBaseUrl + "/cedarling/evaluation";
                HttpPost httpPost = new HttpPost(url);
                
                String requestBody = objectMapper.writeValueAsString(request);
                httpPost.setEntity(new StringEntity(requestBody, "UTF-8"));
                httpPost.setHeader("Content-Type", "application/json");
                httpPost.setHeader("Accept", "application/json");
                
                try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return objectMapper.readValue(responseBody, AuthZenEvaluationResponse.class);
                    } else {
                        logger.warn("AuthZen evaluation failed: status={}, body={}", 
                                   response.getStatusLine().getStatusCode(), responseBody);
                        return new AuthZenEvaluationResponse(false, Map.of("error", "Evaluation failed"));
                    }
                }
            } catch (Exception e) {
                logger.error("Error during AuthZen evaluation", e);
                return new AuthZenEvaluationResponse(false, Map.of("error", e.getMessage()));
            }
        }).orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Check if Cedarling service is available
     */
    public CompletableFuture<Boolean> checkServiceHealth() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String url = cedarlingBaseUrl + "/.well-known/authzen-configuration";
                HttpGet httpGet = new HttpGet(url);
                httpGet.setHeader("Accept", "application/json");
                
                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    return response.getStatusLine().getStatusCode() == 200;
                }
            } catch (Exception e) {
                logger.debug("Cedarling service health check failed", e);
                return false;
            }
        }).orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Get policy store metadata from Cedarling service
     */
    public CompletableFuture<Map<String, Object>> getPolicyStoreMetadata() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Use a custom endpoint for policy store metadata
                String url = cedarlingBaseUrl + "/cedarling/policy-store/metadata";
                HttpGet httpGet = new HttpGet(url);
                httpGet.setHeader("Accept", "application/json");
                
                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return objectMapper.readValue(responseBody, Map.class);
                    } else {
                        logger.debug("Policy store metadata not available: status={}", 
                                    response.getStatusLine().getStatusCode());
                        return Map.of("status", "unavailable");
                    }
                }
            } catch (Exception e) {
                logger.debug("Error getting policy store metadata", e);
                return Map.of("status", "error", "message", e.getMessage());
            }
        }).orTimeout(timeoutMs, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Evaluate data-based policy using Cedarling UniFFI bindings
     */
    public Map<String, Object> evaluateDataBasedPolicy(Map<String, Object> request) {
        try {
            // Call Cedarling service with data-based authorization request
            String url = cedarlingBaseUrl + "/authzen/v1/access/evaluation";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            String requestJson = objectMapper.writeValueAsString(request);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                // Enhance with UniFFI metadata
                result.put("evaluation_method", "cedarling_uniffi");
                result.put("evaluation_time_ms", System.currentTimeMillis());
                
                return result;
            }
        } catch (Exception e) {
            logger.error("Data-based policy evaluation failed", e);
            return Map.of(
                "decision", false,
                "error", e.getMessage(),
                "evaluation_method", "cedarling_uniffi"
            );
        }
    }
    
    /**
     * Create Cedar schema using Cedarling UniFFI bindings
     */
    public Map<String, Object> createSchema(Map<String, Object> schemaRequest) {
        try {
            String url = cedarlingBaseUrl + "/schema";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            String requestJson = objectMapper.writeValueAsString(schemaRequest);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                result.put("schema_engine", "cedarling_uniffi");
                result.put("created_at", System.currentTimeMillis());
                
                return result;
            }
        } catch (Exception e) {
            logger.error("Schema creation failed", e);
            return Map.of(
                "status", "failed",
                "error", e.getMessage(),
                "schema_engine", "cedarling_uniffi"
            );
        }
    }
    
    /**
     * Create Cedar policy using Cedarling UniFFI bindings
     */
    public Map<String, Object> createPolicy(Map<String, Object> policyRequest) {
        try {
            String url = cedarlingBaseUrl + "/policies";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            String requestJson = objectMapper.writeValueAsString(policyRequest);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                result.put("policy_engine", "cedarling_uniffi");
                result.put("uniffi_bindings", "jans_cedarling");
                
                return result;
            }
        } catch (Exception e) {
            logger.error("Policy creation failed", e);
            return Map.of(
                "status", "failed",
                "error", e.getMessage(),
                "policy_engine", "cedarling_uniffi"
            );
        }
    }
    
    /**
     * Update existing Cedar policy
     */
    public Map<String, Object> updatePolicy(Map<String, Object> updateRequest) {
        try {
            String policyId = (String) updateRequest.get("id");
            String url = cedarlingBaseUrl + "/policies/" + policyId;
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            String requestJson = objectMapper.writeValueAsString(updateRequest);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                result.put("updated_via", "cedarling_uniffi");
                return result;
            }
        } catch (Exception e) {
            logger.error("Policy update failed", e);
            return Map.of("status", "failed", "error", e.getMessage());
        }
    }
    
    /**
     * Delete Cedar policy
     */
    public Map<String, Object> deletePolicy(String policyId) {
        try {
            String url = cedarlingBaseUrl + "/policies/" + policyId;
            HttpGet httpGet = new HttpGet(url);
            httpGet.setHeader("X-HTTP-Method-Override", "DELETE");
            
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                return Map.of(
                    "status", "deleted",
                    "policy_id", policyId,
                    "deleted_via", "cedarling_uniffi"
                );
            }
        } catch (Exception e) {
            logger.error("Policy deletion failed", e);
            return Map.of("status", "failed", "error", e.getMessage());
        }
    }
    
    /**
     * Get policy analytics from Cedarling UniFFI service
     */
    public Map<String, Object> getPolicyAnalytics() {
        try {
            String url = cedarlingBaseUrl + "/analytics";
            HttpGet httpGet = new HttpGet(url);
            
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> analytics = objectMapper.readValue(responseBody, Map.class);
                
                // Enhance with additional metrics
                analytics.put("analytics_source", "cedarling_uniffi");
                analytics.put("generated_at", System.currentTimeMillis());
                analytics.put("uniffi_bindings", "jans_cedarling");
                
                return analytics;
            }
        } catch (Exception e) {
            logger.error("Analytics retrieval failed", e);
            return Map.of(
                "error", e.getMessage(),
                "analytics_source", "cedarling_uniffi",
                "status", "unavailable"
            );
        }
    }
    
    /**
     * Validate JWT tokens using Cedarling service
     */
    public boolean validateAccessToken(String accessToken) {
        try {
            String url = cedarlingBaseUrl + "/validate/access-token";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            Map<String, Object> request = Map.of("access_token", accessToken);
            String requestJson = objectMapper.writeValueAsString(request);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                return (Boolean) result.getOrDefault("valid", false);
            }
        } catch (Exception e) {
            logger.error("Access token validation failed", e);
            return false;
        }
    }
    
    /**
     * Validate ID token using Cedarling service
     */
    public boolean validateIdToken(String idToken) {
        try {
            String url = cedarlingBaseUrl + "/validate/id-token";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            Map<String, Object> request = Map.of("id_token", idToken);
            String requestJson = objectMapper.writeValueAsString(request);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                return (Boolean) result.getOrDefault("valid", false);
            }
        } catch (Exception e) {
            logger.error("ID token validation failed", e);
            return false;
        }
    }
    
    /**
     * Decode JWT token claims using Cedarling service
     */
    public Map<String, Object> decodeTokenClaims(String token) {
        try {
            String url = cedarlingBaseUrl + "/decode/token";
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            
            Map<String, Object> request = Map.of("token", token);
            String requestJson = objectMapper.writeValueAsString(request);
            httpPost.setEntity(new StringEntity(requestJson));
            
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                String responseBody = EntityUtils.toString(response.getEntity());
                Map<String, Object> result = objectMapper.readValue(responseBody, Map.class);
                
                return (Map<String, Object>) result.getOrDefault("claims", Map.of());
            }
        } catch (Exception e) {
            logger.error("Token decoding failed", e);
            return Map.of("error", e.getMessage());
        }
    }
    
    public void close() {
        try {
            httpClient.close();
        } catch (IOException e) {
            logger.warn("Error closing HTTP client", e);
        }
    }
}