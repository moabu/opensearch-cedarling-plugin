package org.opensearch.security.cedarling.audit;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * Tests for AuditLogger functionality
 */
public class AuditLoggerTest {
    
    private ThreadPool threadPool;
    private Settings settings;
    private AuditLogger auditLogger;
    
    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        
        threadPool = new TestThreadPool("test");
        settings = Settings.builder()
            .put(CedarlingSecurityPlugin.CEDARLING_AUDIT_ENABLED.getKey(), true)
            .put("cedarling.audit.metrics.enabled", true)
            .put("cedarling.audit.include_request_details", true)
            .put("cedarling.audit.include_policy_details", false)
            .put("cedarling.audit.log_level", "INFO")
            .build();
        
        auditLogger = new AuditLogger(settings, threadPool);
    }
    
    @Test
    public void testAuditLoggerInitialization() {
        assertNotNull(auditLogger);
        assertTrue(auditLogger.isAuditEnabled());
        assertTrue(auditLogger.isMetricsEnabled());
    }
    
    @Test
    public void testDisabledAuditLogger() {
        Settings disabledSettings = Settings.builder()
            .put(CedarlingSecurityPlugin.CEDARLING_AUDIT_ENABLED.getKey(), false)
            .build();
        
        AuditLogger disabledLogger = new AuditLogger(disabledSettings, threadPool);
        
        assertFalse(disabledLogger.isAuditEnabled());
        
        // Should not throw exceptions when logging while disabled
        AuthorizationRequest request = createTestRequest();
        AuthorizationResponse response = new AuthorizationResponse(true, "Test allowed", "policy1");
        
        disabledLogger.logAuthorizationDecision(request, response, 50L, "node1");
        
        // Metrics should still be empty
        AuditMetrics metrics = disabledLogger.getMetrics();
        assertEquals(0, metrics.getTotalRequests());
    }
    
    @Test
    public void testAuthorizationDecisionLogging() throws InterruptedException {
        AuthorizationRequest request = createTestRequest();
        AuthorizationResponse response = new AuthorizationResponse(true, "Access granted", "policy1");
        
        auditLogger.logAuthorizationDecision(request, response, 100L, "node1");
        
        // Wait for async logging to complete
        Thread.sleep(100);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        assertEquals(1, metrics.getTotalRequests());
        assertEquals(1, metrics.getAllowedRequests());
        assertEquals(0, metrics.getDeniedRequests());
    }
    
    @Test
    public void testDeniedAuthorizationLogging() throws InterruptedException {
        AuthorizationRequest request = createTestRequest();
        AuthorizationResponse response = new AuthorizationResponse(false, "Access denied", null);
        
        auditLogger.logAuthorizationDecision(request, response, 75L, "node1");
        
        // Wait for async logging to complete
        Thread.sleep(100);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        assertEquals(1, metrics.getTotalRequests());
        assertEquals(0, metrics.getAllowedRequests());
        assertEquals(1, metrics.getDeniedRequests());
    }
    
    @Test
    public void testMultipleAuthorizationRequests() throws InterruptedException {
        // Log multiple authorization decisions
        for (int i = 0; i < 5; i++) {
            AuthorizationRequest request = createTestRequest("user" + i, "action" + i);
            AuthorizationResponse response = new AuthorizationResponse(i % 2 == 0, "Test response", "policy" + i);
            
            auditLogger.logAuthorizationDecision(request, response, 50L + i, "node1");
        }
        
        // Wait for async logging to complete
        Thread.sleep(200);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        assertEquals(5, metrics.getTotalRequests());
        assertEquals(3, metrics.getAllowedRequests()); // 0, 2, 4
        assertEquals(2, metrics.getDeniedRequests());  // 1, 3
    }
    
    @Test
    public void testMetricsCalculation() throws InterruptedException {
        // Log mixed results
        for (int i = 0; i < 10; i++) {
            AuthorizationRequest request = createTestRequest("user" + i, "ViewIndex");
            AuthorizationResponse response = new AuthorizationResponse(i < 7, "Test response", null);
            
            auditLogger.logAuthorizationDecision(request, response, 100L, "node1");
        }
        
        // Wait for async logging to complete
        Thread.sleep(200);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        assertEquals(10, metrics.getTotalRequests());
        assertEquals(7, metrics.getAllowedRequests());
        assertEquals(3, metrics.getDeniedRequests());
        assertEquals(0.7, metrics.getAllowRate(), 0.01);
        assertEquals(0.3, metrics.getDenyRate(), 0.01);
    }
    
    @Test
    public void testActionMetricsTracking() throws InterruptedException {
        // Log requests for different actions
        auditLogger.logAuthorizationDecision(
            createTestRequest("user1", "ViewIndex"), 
            new AuthorizationResponse(true, "Allowed", null), 100L, "node1"
        );
        auditLogger.logAuthorizationDecision(
            createTestRequest("user2", "ViewIndex"), 
            new AuthorizationResponse(true, "Allowed", null), 100L, "node1"
        );
        auditLogger.logAuthorizationDecision(
            createTestRequest("user3", "CreateIndex"), 
            new AuthorizationResponse(false, "Denied", null), 100L, "node1"
        );
        
        // Wait for async logging to complete
        Thread.sleep(200);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        Map<String, Long> actionMetrics = metrics.getActionMetrics();
        
        assertEquals(Long.valueOf(2), actionMetrics.get("ViewIndex"));
        assertEquals(Long.valueOf(1), actionMetrics.get("CreateIndex"));
    }
    
    @Test
    public void testTenantMetricsTracking() throws InterruptedException {
        // Log requests for different tenants
        auditLogger.logAuthorizationDecision(
            createTestRequestWithTenant("user1", "ViewIndex", "tenant1"), 
            new AuthorizationResponse(true, "Allowed", null), 100L, "node1"
        );
        auditLogger.logAuthorizationDecision(
            createTestRequestWithTenant("user2", "ViewIndex", "tenant1"), 
            new AuthorizationResponse(true, "Allowed", null), 100L, "node1"
        );
        auditLogger.logAuthorizationDecision(
            createTestRequestWithTenant("user3", "ViewIndex", "tenant2"), 
            new AuthorizationResponse(false, "Denied", null), 100L, "node1"
        );
        
        // Wait for async logging to complete
        Thread.sleep(200);
        
        AuditMetrics metrics = auditLogger.getMetrics();
        Map<String, Long> tenantMetrics = metrics.getTenantMetrics();
        
        assertEquals(Long.valueOf(2), tenantMetrics.get("tenant1"));
        assertEquals(Long.valueOf(1), tenantMetrics.get("tenant2"));
    }
    
    @Test
    public void testSecurityEventLogging() {
        Map<String, Object> context = Map.of(
            "user_id", "testuser",
            "failure_count", 5,
            "action", "ViewIndex"
        );
        
        // Should not throw exceptions
        auditLogger.logSecurityEvent(
            SecurityEventType.REPEATED_ACCESS_DENIED,
            "User exceeded failure threshold",
            context
        );
        
        auditLogger.logSecurityEvent(
            SecurityEventType.POLICY_SYNC_SUCCESS,
            "Policy synchronization completed",
            Map.of("policy_count", 10)
        );
    }
    
    @Test
    public void testPolicySyncEventLogging() {
        // Should not throw exceptions
        auditLogger.logPolicySyncEvent("sync", true, "Synchronized 5 policies", 5);
        auditLogger.logPolicySyncEvent("sync", false, "Sync failed due to network error", 0);
    }
    
    @Test
    public void testMetricsReset() throws InterruptedException {
        // Log some requests
        for (int i = 0; i < 3; i++) {
            AuthorizationRequest request = createTestRequest("user" + i, "ViewIndex");
            AuthorizationResponse response = new AuthorizationResponse(true, "Allowed", null);
            auditLogger.logAuthorizationDecision(request, response, 100L, "node1");
        }
        
        // Wait for async logging to complete
        Thread.sleep(100);
        
        AuditMetrics beforeReset = auditLogger.getMetrics();
        assertEquals(3, beforeReset.getTotalRequests());
        
        // Reset metrics
        auditLogger.resetMetrics();
        
        AuditMetrics afterReset = auditLogger.getMetrics();
        assertEquals(0, afterReset.getTotalRequests());
        assertEquals(0, afterReset.getAllowedRequests());
        assertEquals(0, afterReset.getDeniedRequests());
    }
    
    @Test
    public void testSettingsUpdate() {
        assertTrue(auditLogger.isAuditEnabled());
        
        Settings newSettings = Settings.builder()
            .put(CedarlingSecurityPlugin.CEDARLING_AUDIT_ENABLED.getKey(), false)
            .put("cedarling.audit.metrics.enabled", false)
            .build();
        
        auditLogger.updateSettings(newSettings);
        
        assertFalse(auditLogger.isAuditEnabled());
        assertFalse(auditLogger.isMetricsEnabled());
    }
    
    private AuthorizationRequest createTestRequest() {
        return createTestRequest("testuser", "ViewIndex");
    }
    
    private AuthorizationRequest createTestRequest(String userId, String action) {
        return new AuthorizationRequest(
            "User",
            userId,
            action,
            "Index",
            "test-index",
            null, // tenant
            null, // account
            Map.of("timestamp", System.currentTimeMillis())
        );
    }
    
    private AuthorizationRequest createTestRequestWithTenant(String userId, String action, String tenant) {
        return new AuthorizationRequest(
            "User",
            userId,
            action,
            "Index",
            "test-index",
            tenant,
            null, // account
            Map.of("timestamp", System.currentTimeMillis())
        );
    }
    
    public void tearDown() {
        if (threadPool != null) {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }
}