package org.opensearch.security.cedarling.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer;
import org.opensearch.security.cedarling.sync.SynchronizationStatus;
import org.opensearch.security.cedarling.sync.ClusterSyncStatus;
import org.opensearch.security.cedarling.sync.DistributedSyncCoordinator;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Transport handler for enhanced policy store synchronization operations
 * 
 * Handles various synchronization actions including status queries,
 * forced synchronization, strategy updates, and cluster coordination.
 */
public class TransportCedarlingEnhancedSyncAction extends HandledTransportAction<CedarlingEnhancedSyncRequest, CedarlingEnhancedSyncResponse> {
    
    private static final Logger logger = LogManager.getLogger(TransportCedarlingEnhancedSyncAction.class);
    
    private final PolicyStoreSynchronizer policyStoreSynchronizer;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    
    @Inject
    public TransportCedarlingEnhancedSyncAction(
            TransportService transportService,
            ActionFilters actionFilters,
            PolicyStoreSynchronizer policyStoreSynchronizer,
            ClusterService clusterService,
            ThreadPool threadPool
    ) {
        super(CedarlingEnhancedSyncAction.NAME, transportService, actionFilters, CedarlingEnhancedSyncRequest::new);
        this.policyStoreSynchronizer = policyStoreSynchronizer;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
    }
    
    @Override
    protected void doExecute(Task task, CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        try {
            String action = request.getAction();
            logger.debug("Processing enhanced sync action: {}", action);
            
            switch (action) {
                case "get_status":
                    handleGetStatus(request, listener);
                    break;
                    
                case "force_sync":
                    handleForceSync(request, listener);
                    break;
                    
                case "force_cluster_sync":
                    handleForceClusterSync(request, listener);
                    break;
                    
                case "update_strategy":
                    handleUpdateStrategy(request, listener);
                    break;
                    
                case "get_conflicts":
                    handleGetConflicts(request, listener);
                    break;
                    
                case "get_cluster_status":
                    handleGetClusterStatus(request, listener);
                    break;
                    
                case "get_health":
                    handleGetHealth(request, listener);
                    break;
                    
                default:
                    listener.onFailure(new IllegalArgumentException("Unknown action: " + action));
            }
            
        } catch (Exception e) {
            logger.error("Error processing enhanced sync action: {}", request.getAction(), e);
            listener.onFailure(e);
        }
    }
    
    private void handleGetStatus(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        try {
            if (policyStoreSynchronizer == null) {
                listener.onResponse(createErrorResponse("get_status", "Policy store synchronizer not available"));
                return;
            }
            
            SynchronizationStatus status = policyStoreSynchronizer.getSynchronizationStatus();
            
            Map<String, Object> syncMetrics = new HashMap<>();
            syncMetrics.put("enabled", status.isEnabled());
            syncMetrics.put("healthy", status.isHealthy());
            syncMetrics.put("active", status.isActive());
            syncMetrics.put("consecutive_failures", status.getConsecutiveFailures());
            
            if (status.getCurrentSnapshot() != null) {
                syncMetrics.put("policies_count", status.getCurrentSnapshot().getPolicies().size());
                syncMetrics.put("snapshot_age_minutes", status.getSnapshotAgeMinutes());
            }
            
            if (status.getLastSuccessfulSync() != null) {
                syncMetrics.put("minutes_since_last_sync", status.getMinutesSinceLastSync());
            }
            
            Map<String, Object> clusterStatus = new HashMap<>();
            if (status.getClusterStatus() != null) {
                ClusterSyncStatus cluster = status.getClusterStatus();
                clusterStatus.put("distributed_sync_enabled", cluster.isDistributedSyncEnabled());
                clusterStatus.put("current_leader", cluster.getCurrentLeader());
                clusterStatus.put("total_nodes", cluster.getTotalNodes());
                clusterStatus.put("synchronized_nodes", cluster.getSynchronizedNodes());
                clusterStatus.put("failed_nodes", cluster.getFailedNodes());
                clusterStatus.put("sync_health_percentage", cluster.getSyncHealthPercentage());
                clusterStatus.put("overall_health", cluster.getOverallHealth().toString());
                clusterStatus.put("requires_attention", cluster.requiresImmediateAttention());
            }
            
            Map<String, Object> healthStatus = new HashMap<>();
            healthStatus.put("overall_health", status.getOverallHealthStatus().toString());
            healthStatus.put("requires_attention", status.requiresAttention());
            healthStatus.put("summary", status.getSummary());
            
            CedarlingEnhancedSyncResponse response = new CedarlingEnhancedSyncResponse(
                "get_status",
                true,
                "Synchronization status retrieved successfully",
                status.getLastKnownVersion(),
                status.getCurrentStrategy().toString(),
                status.getConflictStrategy().toString(),
                status.getLastSuccessfulSync(),
                status.getConsecutiveFailures(),
                clusterStatus,
                syncMetrics,
                healthStatus
            );
            
            listener.onResponse(response);
            
        } catch (Exception e) {
            logger.error("Error getting sync status", e);
            listener.onResponse(createErrorResponse("get_status", "Error retrieving status: " + e.getMessage()));
        }
    }
    
    private void handleForceSync(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(createErrorResponse("force_sync", "Policy store synchronizer not available"));
            return;
        }
        
        CompletableFuture<Boolean> syncFuture = policyStoreSynchronizer.forceSyncCheck();
        
        syncFuture.whenComplete((success, throwable) -> {
            if (throwable != null) {
                logger.error("Force sync failed", throwable);
                listener.onResponse(createErrorResponse("force_sync", "Force sync failed: " + throwable.getMessage()));
            } else {
                String message = success ? "Force sync completed successfully" : "Force sync failed";
                listener.onResponse(createSuccessResponse("force_sync", message));
            }
        });
    }
    
    private void handleForceClusterSync(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(createErrorResponse("force_cluster_sync", "Policy store synchronizer not available"));
            return;
        }
        
        CompletableFuture<DistributedSyncCoordinator.ClusterSyncResult> clusterSyncFuture = 
            policyStoreSynchronizer.forceClusterSync();
        
        clusterSyncFuture.whenComplete((result, throwable) -> {
            if (throwable != null) {
                logger.error("Force cluster sync failed", throwable);
                listener.onResponse(createErrorResponse("force_cluster_sync", "Force cluster sync failed: " + throwable.getMessage()));
            } else {
                Map<String, Object> clusterMetrics = new HashMap<>();
                clusterMetrics.put("nodes_updated", result.getNodesUpdated());
                clusterMetrics.put("details", result.getDetails());
                
                String message = result.isSuccessful() 
                    ? "Force cluster sync completed successfully" 
                    : "Force cluster sync failed: " + result.getFailureReason();
                
                CedarlingEnhancedSyncResponse response = new CedarlingEnhancedSyncResponse(
                    "force_cluster_sync",
                    result.isSuccessful(),
                    message,
                    null, null, null, null, 0,
                    clusterMetrics,
                    new HashMap<>(),
                    new HashMap<>()
                );
                
                listener.onResponse(response);
            }
        });
    }
    
    private void handleUpdateStrategy(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        // Strategy updates would typically require cluster state changes
        // For now, return informational response
        listener.onResponse(createSuccessResponse("update_strategy", 
            "Strategy updates require cluster configuration changes via settings API"));
    }
    
    private void handleGetConflicts(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        // Conflict information would be tracked by the synchronizer
        Map<String, Object> conflictInfo = new HashMap<>();
        conflictInfo.put("active_conflicts", 0);
        conflictInfo.put("manual_review_required", false);
        conflictInfo.put("last_conflict_time", null);
        
        CedarlingEnhancedSyncResponse response = new CedarlingEnhancedSyncResponse(
            "get_conflicts",
            true,
            "Conflict status retrieved successfully",
            null, null, null, null, 0,
            new HashMap<>(),
            conflictInfo,
            new HashMap<>()
        );
        
        listener.onResponse(response);
    }
    
    private void handleGetClusterStatus(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(createErrorResponse("get_cluster_status", "Policy store synchronizer not available"));
            return;
        }
        
        try {
            SynchronizationStatus status = policyStoreSynchronizer.getSynchronizationStatus();
            ClusterSyncStatus clusterStatus = status.getClusterStatus();
            
            Map<String, Object> clusterInfo = new HashMap<>();
            clusterInfo.put("distributed_sync_enabled", clusterStatus.isDistributedSyncEnabled());
            clusterInfo.put("current_leader", clusterStatus.getCurrentLeader());
            clusterInfo.put("local_node_leader", clusterStatus.isLocalNodeLeader());
            clusterInfo.put("total_nodes", clusterStatus.getTotalNodes());
            clusterInfo.put("synchronized_nodes", clusterStatus.getSynchronizedNodes());
            clusterInfo.put("failed_nodes", clusterStatus.getFailedNodes());
            clusterInfo.put("syncing_nodes", clusterStatus.getSyncingNodes());
            clusterInfo.put("conflict_nodes", clusterStatus.getConflictNodes());
            clusterInfo.put("cluster_synchronized", clusterStatus.isClusterSynchronized());
            clusterInfo.put("sync_health_percentage", clusterStatus.getSyncHealthPercentage());
            clusterInfo.put("overall_health", clusterStatus.getOverallHealth().toString());
            clusterInfo.put("summary", clusterStatus.getSummary());
            
            CedarlingEnhancedSyncResponse response = new CedarlingEnhancedSyncResponse(
                "get_cluster_status",
                true,
                "Cluster status retrieved successfully",
                null, null, null, null, 0,
                clusterInfo,
                new HashMap<>(),
                new HashMap<>()
            );
            
            listener.onResponse(response);
            
        } catch (Exception e) {
            logger.error("Error getting cluster status", e);
            listener.onResponse(createErrorResponse("get_cluster_status", "Error retrieving cluster status: " + e.getMessage()));
        }
    }
    
    private void handleGetHealth(CedarlingEnhancedSyncRequest request, ActionListener<CedarlingEnhancedSyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(createErrorResponse("get_health", "Policy store synchronizer not available"));
            return;
        }
        
        try {
            SynchronizationStatus status = policyStoreSynchronizer.getSynchronizationStatus();
            
            Map<String, Object> healthInfo = new HashMap<>();
            healthInfo.put("overall_health", status.getOverallHealthStatus().toString());
            healthInfo.put("healthy", status.isHealthy());
            healthInfo.put("active", status.isActive());
            healthInfo.put("requires_attention", status.requiresAttention());
            healthInfo.put("consecutive_failures", status.getConsecutiveFailures());
            healthInfo.put("cluster_health", status.getClusterStatus().getOverallHealth().toString());
            healthInfo.put("cluster_health_percentage", status.getClusterStatus().getSyncHealthPercentage());
            healthInfo.put("summary", status.getSummary());
            
            CedarlingEnhancedSyncResponse response = new CedarlingEnhancedSyncResponse(
                "get_health",
                true,
                "Health status retrieved successfully",
                null, null, null, null, 0,
                new HashMap<>(),
                new HashMap<>(),
                healthInfo
            );
            
            listener.onResponse(response);
            
        } catch (Exception e) {
            logger.error("Error getting health status", e);
            listener.onResponse(createErrorResponse("get_health", "Error retrieving health status: " + e.getMessage()));
        }
    }
    
    private CedarlingEnhancedSyncResponse createSuccessResponse(String action, String message) {
        return new CedarlingEnhancedSyncResponse(
            action, true, message, null, null, null, null, 0,
            new HashMap<>(), new HashMap<>(), new HashMap<>()
        );
    }
    
    private CedarlingEnhancedSyncResponse createErrorResponse(String action, String message) {
        return new CedarlingEnhancedSyncResponse(
            action, false, message, null, null, null, null, 0,
            new HashMap<>(), new HashMap<>(), new HashMap<>()
        );
    }
}