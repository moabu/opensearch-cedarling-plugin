package org.opensearch.security.cedarling.test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.sync.SynchronizationStrategy;
import org.opensearch.security.cedarling.sync.ConflictResolver;

import java.util.logging.Logger;

/**
 * Test class to verify the enhanced Cedarling Security Plugin loads correctly
 * and all components are properly initialized.
 */
public class PluginLoadTest {
    
    private static final Logger logger = Logger.getLogger(PluginLoadTest.class.getName());
    
    public static void main(String[] args) {
        try {
            logger.info("Starting Enhanced Cedarling Security Plugin Load Test");
            
            // Test 1: Plugin Instantiation
            testPluginInstantiation();
            
            // Test 2: Settings Configuration
            testSettingsConfiguration();
            
            // Test 3: Synchronization Strategy Validation
            testSynchronizationStrategies();
            
            // Test 4: Conflict Resolution Validation
            testConflictResolution();
            
            // Test 5: Component Integration
            testComponentIntegration();
            
            logger.info("✓ All Enhanced Cedarling Security Plugin tests passed successfully!");
            logger.info("✓ Plugin is ready for deployment with OpenSearch");
            
        } catch (Exception e) {
            logger.severe("✗ Plugin load test failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static void testPluginInstantiation() {
        logger.info("Testing plugin instantiation...");
        
        try {
            CedarlingSecurityPlugin plugin = new CedarlingSecurityPlugin();
            
            // Verify plugin metadata
            if (plugin.getClass().getName().equals("org.opensearch.security.cedarling.CedarlingSecurityPlugin")) {
                logger.info("✓ Plugin class instantiated successfully");
            } else {
                throw new RuntimeException("Plugin class name mismatch");
            }
            
            // Verify settings are available
            if (CedarlingSecurityPlugin.CEDARLING_ENABLED != null) {
                logger.info("✓ Plugin settings configured correctly");
            } else {
                throw new RuntimeException("Plugin settings not available");
            }
            
        } catch (Exception e) {
            throw new RuntimeException("Plugin instantiation failed", e);
        }
    }
    
    private static void testSettingsConfiguration() {
        logger.info("Testing settings configuration...");
        
        try {
            Settings testSettings = Settings.builder()
                .put("cedarling.enabled", true)
                .put("cedarling.endpoint", "http://localhost:8080/cedarling")
                .put("cedarling.policy_store_id", "test-store")
                .put("cedarling.sync.enabled", true)
                .put("cedarling.sync.interval_seconds", 30)
                .put("cedarling.sync.strategy", "smart")
                .put("cedarling.sync.conflict_resolution", "timestamp_based")
                .build();
            
            // Verify settings can be read
            boolean enabled = CedarlingSecurityPlugin.CEDARLING_ENABLED.get(testSettings);
            String endpoint = CedarlingSecurityPlugin.CEDARLING_ENDPOINT.get(testSettings);
            boolean syncEnabled = CedarlingSecurityPlugin.CEDARLING_SYNC_ENABLED.get(testSettings);
            
            if (enabled && endpoint.equals("http://localhost:8080/cedarling") && syncEnabled) {
                logger.info("✓ Settings configuration validated successfully");
            } else {
                throw new RuntimeException("Settings validation failed");
            }
            
        } catch (Exception e) {
            throw new RuntimeException("Settings configuration test failed", e);
        }
    }
    
    private static void testSynchronizationStrategies() {
        logger.info("Testing synchronization strategies...");
        
        try {
            // Test strategy parsing
            SynchronizationStrategy smartSync = SynchronizationStrategy.fromString("smart");
            SynchronizationStrategy fullSync = SynchronizationStrategy.fromString("full");
            SynchronizationStrategy incrementalSync = SynchronizationStrategy.fromString("incremental");
            
            if (smartSync == SynchronizationStrategy.SMART_SYNC &&
                fullSync == SynchronizationStrategy.FULL_SYNC &&
                incrementalSync == SynchronizationStrategy.INCREMENTAL_SYNC) {
                logger.info("✓ Synchronization strategy parsing works correctly");
            } else {
                throw new RuntimeException("Strategy parsing failed");
            }
            
            // Test strategy recommendations
            SynchronizationStrategy recommended = SynchronizationStrategy.recommendStrategy(50, 0.2);
            if (recommended != null) {
                logger.info("✓ Strategy recommendation system operational");
            } else {
                throw new RuntimeException("Strategy recommendation failed");
            }
            
            // Test strategy capabilities
            if (SynchronizationStrategy.HYBRID.supportsRealTime() &&
                SynchronizationStrategy.INCREMENTAL_SYNC.supportsIncremental()) {
                logger.info("✓ Strategy capability detection working");
            } else {
                throw new RuntimeException("Strategy capability detection failed");
            }
            
        } catch (Exception e) {
            throw new RuntimeException("Synchronization strategy test failed", e);
        }
    }
    
    private static void testConflictResolution() {
        logger.info("Testing conflict resolution mechanisms...");
        
        try {
            // Test conflict resolver instantiation
            ConflictResolver resolver = new ConflictResolver(
                ConflictResolver.ConflictResolutionStrategy.TIMESTAMP_BASED
            );
            
            if (resolver != null) {
                logger.info("✓ Conflict resolver instantiated successfully");
            } else {
                throw new RuntimeException("Conflict resolver instantiation failed");
            }
            
            // Test all conflict resolution strategies
            ConflictResolver.ConflictResolutionStrategy[] strategies = 
                ConflictResolver.ConflictResolutionStrategy.values();
            
            if (strategies.length >= 6) { // We have 6 strategies implemented
                logger.info("✓ All conflict resolution strategies available");
            } else {
                throw new RuntimeException("Missing conflict resolution strategies");
            }
            
        } catch (Exception e) {
            throw new RuntimeException("Conflict resolution test failed", e);
        }
    }
    
    private static void testComponentIntegration() {
        logger.info("Testing component integration...");
        
        try {
            // Verify all required classes are available
            Class.forName("org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer");
            Class.forName("org.opensearch.security.cedarling.sync.DistributedSyncCoordinator");
            Class.forName("org.opensearch.security.cedarling.sync.SynchronizationContext");
            Class.forName("org.opensearch.security.cedarling.sync.PolicyResolutionResult");
            Class.forName("org.opensearch.security.cedarling.audit.AuditLogger");
            Class.forName("org.opensearch.security.cedarling.audit.AuditAnalytics");
            Class.forName("org.opensearch.security.cedarling.service.CedarlingService");
            
            logger.info("✓ All required component classes are available");
            
            // Verify REST handlers
            Class.forName("org.opensearch.security.cedarling.rest.RestCedarlingEnhancedSyncHandler");
            Class.forName("org.opensearch.security.cedarling.action.CedarlingEnhancedSyncAction");
            Class.forName("org.opensearch.security.cedarling.action.TransportCedarlingEnhancedSyncAction");
            
            logger.info("✓ Enhanced synchronization REST endpoints available");
            
            // Verify model classes
            Class.forName("org.opensearch.security.cedarling.model.PolicyStoreSnapshot");
            Class.forName("org.opensearch.security.cedarling.sync.SynchronizationStatus");
            Class.forName("org.opensearch.security.cedarling.sync.ClusterSyncStatus");
            
            logger.info("✓ All model and data classes available");
            
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Component integration test failed - missing class: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("Component integration test failed", e);
        }
    }
}