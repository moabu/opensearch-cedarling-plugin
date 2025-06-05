package org.opensearch.security.cedarling.integration;

import org.opensearch.security.cedarling.service.CedarlingClient;
import org.opensearch.security.cedarling.model.AuthZenEvaluationRequest;
import org.opensearch.security.cedarling.model.AuthZenEvaluationResponse;
import org.opensearch.common.logging.Logger;
import org.opensearch.common.logging.Loggers;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Integration test for authentic jans-cedarling service
 * Validates real-world enterprise authorization scenarios
 */
public class CedarlingIntegrationTest {
    
    private static final Logger logger = Loggers.getLogger(CedarlingIntegrationTest.class);
    
    private final CedarlingClient cedarlingClient;
    private final String testSuiteId;
    
    public CedarlingIntegrationTest(String cedarlingBaseUrl, int timeoutMs) {
        this.cedarlingClient = new CedarlingClient(cedarlingBaseUrl, timeoutMs);
        this.testSuiteId = "integration-test-" + System.currentTimeMillis();
    }
    
    /**
     * Run comprehensive integration test suite
     */
    public CompletableFuture<IntegrationTestResult> runIntegrationTests() {
        return CompletableFuture.supplyAsync(() -> {
            IntegrationTestResult result = new IntegrationTestResult(testSuiteId);
            
            try {
                // Test 1: Service connectivity
                logger.info("Running connectivity test...");
                boolean isHealthy = testServiceConnectivity();
                result.addTest("service_connectivity", isHealthy, 
                              isHealthy ? "Service accessible" : "Service unavailable");
                
                if (!isHealthy) {
                    result.setOverallStatus(false);
                    result.setMessage("Cannot connect to Cedarling service");
                    return result;
                }
                
                // Test 2: Well-known configuration
                logger.info("Testing well-known configuration...");
                Map<String, Object> config = testWellKnownConfiguration();
                boolean hasConfig = config != null && config.containsKey("access_evaluation_v1_endpoint");
                result.addTest("well_known_config", hasConfig, 
                              hasConfig ? "Configuration available" : "Configuration missing");
                
                // Test 3: Authorization evaluation scenarios
                logger.info("Testing authorization scenarios...");
                testAuthorizationScenarios(result);
                
                // Test 4: Performance benchmarks
                logger.info("Running performance benchmarks...");
                testPerformanceBenchmarks(result);
                
                result.setOverallStatus(result.getFailedTests() == 0);
                result.setMessage(String.format("Tests completed: %d passed, %d failed", 
                                               result.getPassedTests(), result.getFailedTests()));
                
            } catch (Exception e) {
                logger.error("Integration test suite failed", e);
                result.setOverallStatus(false);
                result.setMessage("Test suite error: " + e.getMessage());
            }
            
            return result;
        });
    }
    
    private boolean testServiceConnectivity() {
        try {
            return cedarlingClient.checkServiceHealth().get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.debug("Service connectivity test failed", e);
            return false;
        }
    }
    
    private Map<String, Object> testWellKnownConfiguration() {
        try {
            return cedarlingClient.getWellKnownConfiguration().get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.debug("Well-known configuration test failed", e);
            return null;
        }
    }
    
    private void testAuthorizationScenarios(IntegrationTestResult result) {
        testAdminUserScenario(result);
        testRegularUserScenario(result);
        testCrossTenantScenario(result);
        testContextBasedScenario(result);
    }
    
    private void testAdminUserScenario(IntegrationTestResult result) {
        try {
            AuthZenEvaluationRequest request = createAdminRequest();
            AuthZenEvaluationResponse response = cedarlingClient.evaluate(request)
                .get(10, TimeUnit.SECONDS);
            
            boolean success = response != null && response.isDecision();
            result.addTest("admin_user_access", success, 
                          success ? "Admin access granted" : "Admin access denied");
                          
        } catch (Exception e) {
            result.addTest("admin_user_access", false, "Test failed: " + e.getMessage());
        }
    }
    
    private void testRegularUserScenario(IntegrationTestResult result) {
        try {
            AuthZenEvaluationRequest request = createRegularUserRequest();
            AuthZenEvaluationResponse response = cedarlingClient.evaluate(request)
                .get(10, TimeUnit.SECONDS);
            
            boolean success = response != null;
            result.addTest("regular_user_access", success, 
                          success ? "Regular user evaluation completed" : "Regular user evaluation failed");
                          
        } catch (Exception e) {
            result.addTest("regular_user_access", false, "Test failed: " + e.getMessage());
        }
    }
    
    private void testCrossTenantScenario(IntegrationTestResult result) {
        try {
            AuthZenEvaluationRequest request = createCrossTenantRequest();
            AuthZenEvaluationResponse response = cedarlingClient.evaluate(request)
                .get(10, TimeUnit.SECONDS);
            
            boolean success = response != null && !response.isDecision();
            result.addTest("cross_tenant_denial", success, 
                          success ? "Cross-tenant access properly denied" : "Cross-tenant access not properly handled");
                          
        } catch (Exception e) {
            result.addTest("cross_tenant_denial", false, "Test failed: " + e.getMessage());
        }
    }
    
    private void testContextBasedScenario(IntegrationTestResult result) {
        try {
            AuthZenEvaluationRequest request = createContextBasedRequest();
            AuthZenEvaluationResponse response = cedarlingClient.evaluate(request)
                .get(10, TimeUnit.SECONDS);
            
            boolean success = response != null;
            result.addTest("context_based_auth", success, 
                          success ? "Context-based authorization completed" : "Context-based authorization failed");
                          
        } catch (Exception e) {
            result.addTest("context_based_auth", false, "Test failed: " + e.getMessage());
        }
    }
    
    private void testPerformanceBenchmarks(IntegrationTestResult result) {
        try {
            long startTime = System.currentTimeMillis();
            int iterations = 10;
            int successCount = 0;
            
            for (int i = 0; i < iterations; i++) {
                AuthZenEvaluationRequest request = createPerformanceTestRequest(i);
                AuthZenEvaluationResponse response = cedarlingClient.evaluate(request)
                    .get(5, TimeUnit.SECONDS);
                if (response != null) {
                    successCount++;
                }
            }
            
            long totalTime = System.currentTimeMillis() - startTime;
            double avgTime = (double) totalTime / iterations;
            boolean success = successCount >= iterations * 0.8;
            
            result.addTest("performance_benchmark", success, 
                          String.format("Avg response time: %.1fms, Success rate: %d%%", 
                                      avgTime, (successCount * 100) / iterations));
                          
        } catch (Exception e) {
            result.addTest("performance_benchmark", false, "Benchmark failed: " + e.getMessage());
        }
    }
    
    private AuthZenEvaluationRequest createAdminRequest() {
        AuthZenEvaluationRequest.Subject subject = new AuthZenEvaluationRequest.Subject(
            "User", "admin@enterprise.com", 
            Map.of("tenant", "enterprise", "roles", Arrays.asList("admin", "data-scientist"))
        );
        
        AuthZenEvaluationRequest.Resource resource = new AuthZenEvaluationRequest.Resource(
            "Document", "sensitive-analytics-2025",
            Map.of("tenant", "enterprise", "classification", "confidential")
        );
        
        AuthZenEvaluationRequest.Action action = new AuthZenEvaluationRequest.Action(
            "read", Map.of("operation", "view")
        );
        
        Map<String, Object> context = Map.of(
            "timestamp", System.currentTimeMillis(),
            "ip_address", "10.0.1.100",
            "user_agent", "OpenSearch-Plugin-Test"
        );
        
        return new AuthZenEvaluationRequest(subject, resource, action, context);
    }
    
    private AuthZenEvaluationRequest createRegularUserRequest() {
        AuthZenEvaluationRequest.Subject subject = new AuthZenEvaluationRequest.Subject(
            "User", "user@enterprise.com", 
            Map.of("tenant", "enterprise", "roles", Arrays.asList("user"))
        );
        
        AuthZenEvaluationRequest.Resource resource = new AuthZenEvaluationRequest.Resource(
            "Document", "public-announcement",
            Map.of("tenant", "enterprise", "classification", "public")
        );
        
        AuthZenEvaluationRequest.Action action = new AuthZenEvaluationRequest.Action(
            "read", Map.of("operation", "view")
        );
        
        return new AuthZenEvaluationRequest(subject, resource, action, Map.of());
    }
    
    private AuthZenEvaluationRequest createCrossTenantRequest() {
        AuthZenEvaluationRequest.Subject subject = new AuthZenEvaluationRequest.Subject(
            "User", "external@other-corp.com", 
            Map.of("tenant", "other-corp", "roles", Arrays.asList("user"))
        );
        
        AuthZenEvaluationRequest.Resource resource = new AuthZenEvaluationRequest.Resource(
            "Document", "enterprise-confidential",
            Map.of("tenant", "enterprise", "classification", "confidential")
        );
        
        AuthZenEvaluationRequest.Action action = new AuthZenEvaluationRequest.Action(
            "read", Map.of("operation", "view")
        );
        
        return new AuthZenEvaluationRequest(subject, resource, action, Map.of());
    }
    
    private AuthZenEvaluationRequest createContextBasedRequest() {
        AuthZenEvaluationRequest.Subject subject = new AuthZenEvaluationRequest.Subject(
            "User", "analyst@enterprise.com", 
            Map.of("tenant", "enterprise", "roles", Arrays.asList("analyst"))
        );
        
        AuthZenEvaluationRequest.Resource resource = new AuthZenEvaluationRequest.Resource(
            "Dataset", "customer-analytics",
            Map.of("tenant", "enterprise", "sensitivity", "high")
        );
        
        AuthZenEvaluationRequest.Action action = new AuthZenEvaluationRequest.Action(
            "analyze", Map.of("operation", "aggregate")
        );
        
        Map<String, Object> context = Map.of(
            "timestamp", System.currentTimeMillis(),
            "business_hours", true,
            "location", "office"
        );
        
        return new AuthZenEvaluationRequest(subject, resource, action, context);
    }
    
    private AuthZenEvaluationRequest createPerformanceTestRequest(int iteration) {
        AuthZenEvaluationRequest.Subject subject = new AuthZenEvaluationRequest.Subject(
            "User", "perf-test-" + iteration + "@enterprise.com", 
            Map.of("tenant", "enterprise", "roles", Arrays.asList("user"))
        );
        
        AuthZenEvaluationRequest.Resource resource = new AuthZenEvaluationRequest.Resource(
            "Document", "perf-test-doc-" + iteration,
            Map.of("tenant", "enterprise")
        );
        
        AuthZenEvaluationRequest.Action action = new AuthZenEvaluationRequest.Action(
            "read", Map.of()
        );
        
        return new AuthZenEvaluationRequest(subject, resource, action, Map.of());
    }
    
    public void close() {
        cedarlingClient.close();
    }
    
    public static class IntegrationTestResult {
        private final String testSuiteId;
        private final Map<String, TestCase> testCases;
        private boolean overallStatus;
        private String message;
        private long timestamp;
        
        public IntegrationTestResult(String testSuiteId) {
            this.testSuiteId = testSuiteId;
            this.testCases = new HashMap<>();
            this.timestamp = System.currentTimeMillis();
        }
        
        public void addTest(String testName, boolean passed, String details) {
            testCases.put(testName, new TestCase(testName, passed, details));
        }
        
        public int getPassedTests() {
            return (int) testCases.values().stream().filter(TestCase::isPassed).count();
        }
        
        public int getFailedTests() {
            return (int) testCases.values().stream().filter(tc -> !tc.isPassed()).count();
        }
        
        public String getTestSuiteId() { return testSuiteId; }
        public Map<String, TestCase> getTestCases() { return testCases; }
        public boolean isOverallStatus() { return overallStatus; }
        public void setOverallStatus(boolean overallStatus) { this.overallStatus = overallStatus; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public long getTimestamp() { return timestamp; }
        
        public static class TestCase {
            private final String name;
            private final boolean passed;
            private final String details;
            
            public TestCase(String name, boolean passed, String details) {
                this.name = name;
                this.passed = passed;
                this.details = details;
            }
            
            public String getName() { return name; }
            public boolean isPassed() { return passed; }
            public String getDetails() { return details; }
        }
    }
}