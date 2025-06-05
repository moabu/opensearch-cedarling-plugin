package org.opensearch.security.cedarling.sync;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.model.PolicyStoreSnapshot;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Manages live synchronization of Cedar policy store with Cedarling service
 * 
 * Features:
 * - Periodic policy store polling
 * - Change detection via version/timestamp comparison
 * - Automatic policy cache invalidation
 * - Fallback to cached policies on service unavailability
 * - Configurable sync intervals
 */
public class PolicyStoreSynchronizer {
    
    private static final Logger logger = LogManager.getLogger(PolicyStoreSynchronizer.class);
    
    private final Settings settings;
    private final ThreadPool threadPool;
    private final CedarlingService cedarlingService;
    private final ClusterService clusterService;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    // Enhanced synchronization components
    private final ConflictResolver conflictResolver;
    private final DistributedSyncCoordinator distributedCoordinator;
    
    private final AtomicReference<PolicyStoreSnapshot> currentSnapshot;
    private final AtomicReference<ScheduledFuture<?>> syncTask;
    
    // Configuration settings
    private volatile String cedarlingEndpoint;
    private volatile String policyStoreId;
    private volatile long syncIntervalSeconds;
    private volatile boolean enabled;
    private volatile SynchronizationStrategy syncStrategy;
    private volatile ConflictResolver.ConflictResolutionStrategy conflictStrategy;
    
    // State tracking
    private volatile String lastKnownVersion;
    private volatile Instant lastSuccessfulSync;
    private volatile int consecutiveFailures;
    private volatile boolean adaptiveStrategyEnabled;
    
    public PolicyStoreSynchronizer(
            Settings settings, 
            ThreadPool threadPool, 
            CedarlingService cedarlingService,
            ClusterService clusterService,
            CloseableHttpClient httpClient
    ) {
        this.settings = settings;
        this.threadPool = threadPool;
        this.cedarlingService = cedarlingService;
        this.clusterService = clusterService;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper();
        this.currentSnapshot = new AtomicReference<>();
        this.syncTask = new AtomicReference<>();
        
        // Initialize enhanced synchronization components
        this.conflictResolver = new ConflictResolver(ConflictResolver.ConflictResolutionStrategy.TIMESTAMP_BASED);
        this.distributedCoordinator = new DistributedSyncCoordinator(clusterService, threadPool, settings);
        
        updateSettings(settings);
        
        logger.info("Enhanced policy store synchronizer initialized - strategy: {}, interval: {}s", 
                   syncStrategy, syncIntervalSeconds);
    }
    
    public void updateSettings(Settings settings) {
        this.cedarlingEndpoint = CedarlingSecurityPlugin.CEDARLING_ENDPOINT.get(settings);
        this.policyStoreId = CedarlingSecurityPlugin.CEDARLING_POLICY_STORE_ID.get(settings);
        this.enabled = CedarlingSecurityPlugin.CEDARLING_ENABLED.get(settings);
        
        // Get sync interval from settings (default 30 seconds)
        this.syncIntervalSeconds = settings.getAsLong("cedarling.sync.interval_seconds", 30L);
        
        // Enhanced synchronization settings
        String strategyStr = settings.get("cedarling.sync.strategy", "smart");
        this.syncStrategy = SynchronizationStrategy.fromString(strategyStr);
        
        String conflictStrategyStr = settings.get("cedarling.sync.conflict_resolution", "timestamp_based");
        this.conflictStrategy = parseConflictStrategy(conflictStrategyStr);
        
        this.adaptiveStrategyEnabled = settings.getAsBoolean("cedarling.sync.adaptive_strategy", true);
        
        // Update distributed coordinator settings
        distributedCoordinator.updateSettings(settings);
        
        logger.debug("Updated enhanced sync settings - enabled: {}, strategy: {}, conflict: {}, interval: {}s", 
                    enabled, syncStrategy, conflictStrategy, syncIntervalSeconds);
    }
    
    /**
     * Parse conflict resolution strategy from configuration string
     */
    private ConflictResolver.ConflictResolutionStrategy parseConflictStrategy(String strategy) {
        switch (strategy.toLowerCase()) {
            case "remote_wins":
                return ConflictResolver.ConflictResolutionStrategy.REMOTE_WINS;
            case "local_wins":
                return ConflictResolver.ConflictResolutionStrategy.LOCAL_WINS;
            case "timestamp_based":
                return ConflictResolver.ConflictResolutionStrategy.TIMESTAMP_BASED;
            case "merge_policies":
                return ConflictResolver.ConflictResolutionStrategy.MERGE_POLICIES;
            case "manual_review":
                return ConflictResolver.ConflictResolutionStrategy.MANUAL_REVIEW;
            case "fail_safe":
                return ConflictResolver.ConflictResolutionStrategy.FAIL_SAFE;
            default:
                return ConflictResolver.ConflictResolutionStrategy.TIMESTAMP_BASED;
        }
    }
    
    /**
     * Start the policy store synchronization process
     */
    public void start() {
        if (!enabled) {
            logger.info("Policy store synchronization disabled");
            return;
        }
        
        // Perform initial sync
        performInitialSync();
        
        // Schedule periodic sync
        ScheduledFuture<?> task = threadPool.scheduleWithFixedDelay(
            this::performPeriodicSync,
            syncIntervalSeconds,
            syncIntervalSeconds,
            TimeUnit.SECONDS,
            ThreadPool.Names.GENERIC
        );
        
        ScheduledFuture<?> oldTask = syncTask.getAndSet(task);
        if (oldTask != null) {
            oldTask.cancel(false);
        }
        
        logger.info("Policy store synchronization started with {}s interval", syncIntervalSeconds);
    }
    
    /**
     * Stop the policy store synchronization
     */
    public void stop() {
        ScheduledFuture<?> task = syncTask.getAndSet(null);
        if (task != null) {
            task.cancel(false);
            logger.info("Policy store synchronization stopped");
        }
    }
    
    /**
     * Get the current policy store snapshot
     */
    public PolicyStoreSnapshot getCurrentSnapshot() {
        return currentSnapshot.get();
    }
    
    /**
     * Force a synchronization check
     */
    public CompletableFuture<Boolean> forceSyncCheck() {
        return CompletableFuture.supplyAsync(this::performSyncCheck, threadPool.executor(ThreadPool.Names.GENERIC));
    }
    
    private void performInitialSync() {
        try {
            logger.info("Performing initial policy store synchronization");
            boolean updated = performSyncCheck();
            
            if (updated) {
                logger.info("Initial policy store sync completed successfully");
            } else {
                logger.warn("Initial policy store sync failed - will retry on next interval");
            }
        } catch (Exception e) {
            logger.error("Error during initial policy store sync", e);
        }
    }
    
    private void performPeriodicSync() {
        try {
            logger.debug("Performing periodic policy store sync check");
            boolean updated = performSyncCheck();
            
            if (updated) {
                logger.info("Policy store updated during periodic sync");
            }
        } catch (Exception e) {
            logger.error("Error during periodic policy store sync", e);
        }
    }
    
    private boolean performSyncCheck() {
        try {
            // Create synchronization context
            SynchronizationContext context = new SynchronizationContext(
                clusterService.localNode().getId(),
                determineSyncStrategy(),
                SynchronizationContext.SynchronizationTrigger.SCHEDULED,
                consecutiveFailures + 1
            );
            
            context.setClusterMaster(clusterService.state().nodes().isLocalNodeElectedMaster());
            
            logger.debug("Starting enhanced sync check with strategy: {}", context.getStrategy());
            
            // Step 1: Fetch remote policy store based on strategy
            PolicyStoreSnapshot remoteSnapshot = fetchPolicyStoreWithStrategy(context);
            
            if (remoteSnapshot == null) {
                consecutiveFailures++;
                logger.warn("Failed to fetch remote policy store - attempt {}", consecutiveFailures);
                
                // Adaptive strategy: fallback to simpler strategy on failures
                if (adaptiveStrategyEnabled && consecutiveFailures > 2) {
                    adaptSyncStrategy();
                }
                return false;
            }
            
            context.setPoliciesProcessed(remoteSnapshot.getPolicies().size());
            
            // Step 2: Resolve conflicts if local snapshot exists
            PolicyStoreSnapshot localSnapshot = currentSnapshot.get();
            PolicyResolutionResult resolution = resolveConflicts(localSnapshot, remoteSnapshot, context);
            
            if (!resolution.isSuccessful()) {
                logger.warn("Conflict resolution failed: {}", resolution.getReason());
                return handleConflictResolutionFailure(resolution, context);
            }
            
            // Step 3: Apply resolved snapshot
            PolicyStoreSnapshot finalSnapshot = resolution.getResolvedSnapshot();
            
            // Step 4: Coordinate cluster-wide sync if needed
            boolean clusterSyncResult = true;
            if (context.isClusterMaster() && shouldCoordinateClusterSync(finalSnapshot)) {
                DistributedSyncCoordinator.ClusterSyncResult clusterResult = 
                    distributedCoordinator.coordinateClusterSync(finalSnapshot, context).join();
                clusterSyncResult = clusterResult.isSuccessful();
                
                if (!clusterSyncResult) {
                    logger.warn("Cluster synchronization failed: {}", clusterResult.getFailureReason());
                }
            }
            
            // Step 5: Apply the snapshot locally
            if (resolution.shouldProceedWithSync() && clusterSyncResult) {
                applyPolicySnapshot(finalSnapshot, context);
                
                // Reset failure counter on success
                consecutiveFailures = 0;
                lastSuccessfulSync = Instant.now();
                
                logger.info("Enhanced policy sync completed - version: {}, policies: {}, strategy: {}, duration: {}ms", 
                           finalSnapshot.getVersion(), finalSnapshot.getPolicies().size(), 
                           context.getStrategy(), context.getElapsedTimeMs());
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            consecutiveFailures++;
            logger.error("Enhanced sync check failed - attempt {}", consecutiveFailures, e);
            return false;
        }
    }
    
    /**
     * Determine the optimal synchronization strategy based on current conditions
     */
    private SynchronizationStrategy determineSyncStrategy() {
        if (!adaptiveStrategyEnabled) {
            return syncStrategy;
        }
        
        // Adaptive strategy selection based on current conditions
        PolicyStoreSnapshot current = currentSnapshot.get();
        int currentPolicyCount = current != null ? current.getPolicies().size() : 0;
        
        // Calculate change frequency based on recent sync history
        double changeFrequency = calculateChangeFrequency();
        
        // Use recommended strategy based on conditions
        SynchronizationStrategy recommended = SynchronizationStrategy.recommendStrategy(
            currentPolicyCount, changeFrequency
        );
        
        logger.debug("Adaptive strategy selection - current: {}, recommended: {}, policies: {}, change_freq: {}", 
                    syncStrategy, recommended, currentPolicyCount, changeFrequency);
        
        return recommended;
    }
    
    /**
     * Fetch policy store using the selected strategy
     */
    private PolicyStoreSnapshot fetchPolicyStoreWithStrategy(SynchronizationContext context) {
        SynchronizationStrategy strategy = context.getStrategy();
        
        try {
            switch (strategy) {
                case FULL_SYNC:
                    return fetchFullPolicyStore();
                    
                case INCREMENTAL_SYNC:
                    return fetchIncrementalPolicyStore(context);
                    
                case SMART_SYNC:
                    return fetchSmartPolicyStore(context);
                    
                case EVENT_DRIVEN:
                    return fetchEventDrivenPolicyStore(context);
                    
                case HYBRID:
                    return fetchHybridPolicyStore(context);
                    
                default:
                    return fetchFullPolicyStore();
            }
        } catch (Exception e) {
            logger.error("Failed to fetch policy store with strategy: {}", strategy, e);
            return null;
        }
    }
    
    /**
     * Resolve conflicts between local and remote snapshots
     */
    private PolicyResolutionResult resolveConflicts(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            SynchronizationContext context
    ) {
        return conflictResolver.resolveConflicts(localSnapshot, remoteSnapshot, context);
    }
    
    /**
     * Handle conflict resolution failure
     */
    private boolean handleConflictResolutionFailure(
            PolicyResolutionResult resolution,
            SynchronizationContext context
    ) {
        if (resolution.requiresManualIntervention()) {
            logger.error("Manual intervention required for policy conflicts: {}", 
                        resolution.getUnresolvedConflicts());
            // In production, this would trigger alerts/notifications
            return false;
        }
        
        // For other failures, log and continue
        logger.warn("Conflict resolution failed, skipping sync: {}", resolution.getReason());
        return false;
    }
    
    /**
     * Check if cluster-wide synchronization should be coordinated
     */
    private boolean shouldCoordinateClusterSync(PolicyStoreSnapshot snapshot) {
        // Coordinate if this is a significant policy update
        PolicyStoreSnapshot current = currentSnapshot.get();
        
        if (current == null) {
            return true; // First sync
        }
        
        // Check for significant changes
        int currentPolicyCount = current.getPolicies().size();
        int newPolicyCount = snapshot.getPolicies().size();
        
        // Coordinate if policy count changed significantly or version differs
        return Math.abs(newPolicyCount - currentPolicyCount) > 0 || 
               !current.getVersion().equals(snapshot.getVersion());
    }
    
    /**
     * Apply the resolved policy snapshot
     */
    private void applyPolicySnapshot(PolicyStoreSnapshot snapshot, SynchronizationContext context) {
        PolicyStoreSnapshot oldSnapshot = currentSnapshot.getAndSet(snapshot);
        lastKnownVersion = snapshot.getVersion();
        
        // Notify about policy update
        notifyPolicyUpdate(oldSnapshot, snapshot);
        
        logger.debug("Applied policy snapshot - version: {}, policies: {}", 
                    snapshot.getVersion(), snapshot.getPolicies().size());
    }
    
    /**
     * Calculate change frequency for adaptive strategy
     */
    private double calculateChangeFrequency() {
        // Simplified calculation - in production would track actual change history
        if (consecutiveFailures > 0) {
            return 0.1; // Low frequency if there are failures
        }
        
        if (lastSuccessfulSync != null) {
            long minutesSinceLastSync = 
                (Instant.now().toEpochMilli() - lastSuccessfulSync.toEpochMilli()) / (1000 * 60);
            
            if (minutesSinceLastSync < 5) {
                return 0.8; // High frequency
            } else if (minutesSinceLastSync < 30) {
                return 0.4; // Medium frequency
            }
        }
        
        return 0.1; // Low frequency
    }
    
    /**
     * Adapt synchronization strategy based on failure patterns
     */
    private void adaptSyncStrategy() {
        SynchronizationStrategy currentStrategy = syncStrategy;
        
        // Fallback to simpler strategies on repeated failures
        switch (currentStrategy) {
            case SMART_SYNC:
            case HYBRID:
                syncStrategy = SynchronizationStrategy.INCREMENTAL_SYNC;
                break;
            case INCREMENTAL_SYNC:
            case EVENT_DRIVEN:
                syncStrategy = SynchronizationStrategy.FULL_SYNC;
                break;
            default:
                // Already at simplest strategy
                break;
        }
        
        if (!currentStrategy.equals(syncStrategy)) {
            logger.info("Adapted sync strategy from {} to {} due to consecutive failures", 
                       currentStrategy, syncStrategy);
        }
    }
    
    /**
     * Fetch full policy store snapshot
     */
    private PolicyStoreSnapshot fetchFullPolicyStore() throws IOException {
        return fetchPolicyStoreSnapshot(); // Use existing implementation
    }
    
    /**
     * Fetch incremental policy store updates
     */
    private PolicyStoreSnapshot fetchIncrementalPolicyStore(SynchronizationContext context) throws IOException {
        // First check metadata to see if incremental is possible
        PolicyStoreMetadata metadata = fetchPolicyStoreMetadata();
        if (metadata == null) {
            return null;
        }
        
        PolicyStoreSnapshot current = currentSnapshot.get();
        if (current == null || !metadata.getVersion().equals(current.getVersion())) {
            // Need full sync if no current version or versions differ significantly
            return fetchFullPolicyStore();
        }
        
        // For incremental sync, we would fetch only changed policies
        // For now, fallback to full sync
        logger.debug("Incremental sync not available, falling back to full sync");
        return fetchFullPolicyStore();
    }
    
    /**
     * Fetch policy store using smart strategy
     */
    private PolicyStoreSnapshot fetchSmartPolicyStore(SynchronizationContext context) throws IOException {
        // Smart strategy chooses between full and incremental based on conditions
        PolicyStoreMetadata metadata = fetchPolicyStoreMetadata();
        if (metadata == null) {
            return null;
        }
        
        PolicyStoreSnapshot current = currentSnapshot.get();
        if (current == null) {
            return fetchFullPolicyStore();
        }
        
        // Decide based on change volume
        int currentPolicyCount = current.getPolicies().size();
        int newPolicyCount = metadata.getPolicyCount();
        
        double changeRatio = Math.abs(newPolicyCount - currentPolicyCount) / (double) currentPolicyCount;
        
        if (changeRatio > 0.2) {
            // More than 20% change - use full sync
            logger.debug("Smart sync chose full sync due to high change ratio: {}", changeRatio);
            return fetchFullPolicyStore();
        } else {
            // Small changes - attempt incremental
            logger.debug("Smart sync chose incremental sync due to low change ratio: {}", changeRatio);
            return fetchIncrementalPolicyStore(context);
        }
    }
    
    /**
     * Fetch policy store using event-driven strategy
     */
    private PolicyStoreSnapshot fetchEventDrivenPolicyStore(SynchronizationContext context) throws IOException {
        // Event-driven would normally receive webhooks/notifications
        // For scheduled sync, fallback to metadata check + full sync
        logger.debug("Event-driven sync falling back to metadata check");
        
        PolicyStoreMetadata metadata = fetchPolicyStoreMetadata();
        if (metadata == null) {
            return null;
        }
        
        if (isUpdateNeeded(metadata)) {
            return fetchFullPolicyStore();
        }
        
        return null; // No update needed
    }
    
    /**
     * Fetch policy store using hybrid strategy
     */
    private PolicyStoreSnapshot fetchHybridPolicyStore(SynchronizationContext context) throws IOException {
        // Hybrid combines event-driven with periodic full sync
        // For this implementation, use smart sync logic
        return fetchSmartPolicyStore(context);
    }
    
    /**
     * Get comprehensive synchronization status including cluster state
     */
    public SynchronizationStatus getSynchronizationStatus() {
        ClusterSyncStatus clusterStatus = distributedCoordinator.getClusterSyncStatus();
        
        return new SynchronizationStatus(
            enabled,
            syncStrategy,
            conflictStrategy,
            currentSnapshot.get(),
            lastKnownVersion,
            lastSuccessfulSync,
            consecutiveFailures,
            clusterStatus
        );
    }
    
    /**
     * Force a cluster-wide synchronization
     */
    public CompletableFuture<DistributedSyncCoordinator.ClusterSyncResult> forceClusterSync() {
        return distributedCoordinator.forceClusterSync();
    }
    
    private PolicyStoreMetadata fetchPolicyStoreMetadata() throws IOException {
        String url = cedarlingEndpoint + "/policy_store/" + policyStoreId + "/metadata";
        HttpGet httpGet = new HttpGet(url);
        
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                String responseBody = EntityUtils.toString(response.getEntity());
                JsonNode jsonNode = objectMapper.readTree(responseBody);
                
                return new PolicyStoreMetadata(
                    jsonNode.get("version").asText(),
                    jsonNode.get("last_modified").asText(),
                    jsonNode.get("policy_count").asInt(),
                    jsonNode.get("checksum").asText()
                );
            } else {
                logger.warn("Failed to fetch policy store metadata - status: {}", 
                           response.getStatusLine().getStatusCode());
                return null;
            }
        }
    }
    
    private PolicyStoreSnapshot fetchPolicyStoreSnapshot() throws IOException {
        String url = cedarlingEndpoint + "/policy_store/" + policyStoreId + "/snapshot";
        HttpGet httpGet = new HttpGet(url);
        
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            if (response.getStatusLine().getStatusCode() == 200) {
                String responseBody = EntityUtils.toString(response.getEntity());
                return objectMapper.readValue(responseBody, PolicyStoreSnapshot.class);
            } else {
                logger.warn("Failed to fetch policy store snapshot - status: {}", 
                           response.getStatusLine().getStatusCode());
                return null;
            }
        }
    }
    
    private boolean isUpdateNeeded(PolicyStoreMetadata metadata) {
        // Check if this is the first sync
        if (lastKnownVersion == null) {
            return true;
        }
        
        // Compare versions
        if (!lastKnownVersion.equals(metadata.getVersion())) {
            return true;
        }
        
        // Check if too much time has passed since last sync (failsafe)
        if (lastSuccessfulSync != null) {
            long minutesSinceLastSync = (Instant.now().toEpochMilli() - lastSuccessfulSync.toEpochMilli()) / 60000;
            if (minutesSinceLastSync > 60) { // Force refresh after 1 hour
                logger.info("Forcing policy refresh after {} minutes", minutesSinceLastSync);
                return true;
            }
        }
        
        return false;
    }
    
    private void notifyPolicyUpdate(PolicyStoreSnapshot oldSnapshot, PolicyStoreSnapshot newSnapshot) {
        try {
            // Calculate changes
            int oldPolicyCount = oldSnapshot != null ? oldSnapshot.getPolicies().size() : 0;
            int newPolicyCount = newSnapshot.getPolicies().size();
            int changeCount = newPolicyCount - oldPolicyCount;
            
            // Log policy changes
            if (changeCount > 0) {
                logger.info("Policy store updated: {} new policies added", changeCount);
            } else if (changeCount < 0) {
                logger.info("Policy store updated: {} policies removed", Math.abs(changeCount));
            } else {
                logger.info("Policy store updated: policies modified");
            }
            
            // Invalidate any cached authorization decisions in CedarlingService
            cedarlingService.invalidateAuthorizationCache();
            
            // Publish cluster state update for other nodes
            publishPolicyUpdateEvent(newSnapshot.getVersion(), newSnapshot.getLastModified());
            
        } catch (Exception e) {
            logger.error("Error notifying about policy update", e);
        }
    }
    
    private void publishPolicyUpdateEvent(String version, String lastModified) {
        // In a real implementation, this would publish a cluster event
        // so other OpenSearch nodes can also update their policy caches
        logger.debug("Publishing policy update event - version: {}", version);
    }
    
    public boolean isHealthy() {
        PolicyStoreSnapshot snapshot = currentSnapshot.get();
        
        // Check if we have a recent snapshot
        if (snapshot == null) {
            return false;
        }
        
        // Check if last sync was recent
        if (lastSuccessfulSync != null) {
            long minutesSinceLastSync = (Instant.now().toEpochMilli() - lastSuccessfulSync.toEpochMilli()) / 60000;
            return minutesSinceLastSync < (syncIntervalSeconds / 60) * 3; // Allow 3x sync interval
        }
        
        return false;
    }
    
    public SynchronizationStatus getStatus() {
        PolicyStoreSnapshot snapshot = currentSnapshot.get();
        
        return new SynchronizationStatus(
            enabled,
            syncIntervalSeconds,
            lastKnownVersion,
            lastSuccessfulSync,
            snapshot != null ? snapshot.getPolicies().size() : 0,
            isHealthy()
        );
    }
    
    /**
     * Metadata about the policy store for change detection
     */
    private static class PolicyStoreMetadata {
        private final String version;
        private final String lastModified;
        private final int policyCount;
        private final String checksum;
        
        public PolicyStoreMetadata(String version, String lastModified, int policyCount, String checksum) {
            this.version = version;
            this.lastModified = lastModified;
            this.policyCount = policyCount;
            this.checksum = checksum;
        }
        
        public String getVersion() { return version; }
        public String getLastModified() { return lastModified; }
        public int getPolicyCount() { return policyCount; }
        public String getChecksum() { return checksum; }
    }
    
    /**
     * Status information about the synchronization process
     */
    public static class SynchronizationStatus {
        private final boolean enabled;
        private final long syncIntervalSeconds;
        private final String currentVersion;
        private final Instant lastSync;
        private final int policyCount;
        private final boolean healthy;
        
        public SynchronizationStatus(boolean enabled, long syncIntervalSeconds, String currentVersion, 
                                   Instant lastSync, int policyCount, boolean healthy) {
            this.enabled = enabled;
            this.syncIntervalSeconds = syncIntervalSeconds;
            this.currentVersion = currentVersion;
            this.lastSync = lastSync;
            this.policyCount = policyCount;
            this.healthy = healthy;
        }
        
        public boolean isEnabled() { return enabled; }
        public long getSyncIntervalSeconds() { return syncIntervalSeconds; }
        public String getCurrentVersion() { return currentVersion; }
        public Instant getLastSync() { return lastSync; }
        public int getPolicyCount() { return policyCount; }
        public boolean isHealthy() { return healthy; }
    }
}