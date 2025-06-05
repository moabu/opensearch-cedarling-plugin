package org.opensearch.security.cedarling.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingEnhancedSyncAction;
import org.opensearch.security.cedarling.action.CedarlingEnhancedSyncRequest;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * REST handler for enhanced policy store synchronization operations
 * 
 * Endpoints:
 * GET /_plugins/_cedarling/sync/status - Get comprehensive sync status
 * POST /_plugins/_cedarling/sync/force - Force immediate synchronization
 * POST /_plugins/_cedarling/sync/cluster/force - Force cluster-wide sync
 * PUT /_plugins/_cedarling/sync/strategy - Update synchronization strategy
 * GET /_plugins/_cedarling/sync/conflicts - Get conflict resolution status
 */
public class RestCedarlingEnhancedSyncHandler extends BaseRestHandler {
    
    private static final Logger logger = LogManager.getLogger(RestCedarlingEnhancedSyncHandler.class);
    
    @Override
    public String getName() {
        return "cedarling_enhanced_sync_handler";
    }
    
    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, "/_plugins/_cedarling/sync/status"),
            new Route(POST, "/_plugins/_cedarling/sync/force"),
            new Route(POST, "/_plugins/_cedarling/sync/cluster/force"),
            new Route(PUT, "/_plugins/_cedarling/sync/strategy"),
            new Route(GET, "/_plugins/_cedarling/sync/conflicts"),
            new Route(GET, "/_plugins/_cedarling/sync/cluster/status"),
            new Route(GET, "/_plugins/_cedarling/sync/health")
        );
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String action = determineAction(request);
        
        // Parse request parameters
        String strategy = request.param("strategy");
        String conflictResolution = request.param("conflict_resolution");
        boolean includeClusterState = request.paramAsBoolean("include_cluster", false);
        boolean detailedStatus = request.paramAsBoolean("detailed", false);
        
        CedarlingEnhancedSyncRequest syncRequest = new CedarlingEnhancedSyncRequest(
            action,
            strategy,
            conflictResolution,
            includeClusterState,
            detailedStatus
        );
        
        return channel -> client.execute(
            CedarlingEnhancedSyncAction.INSTANCE,
            syncRequest,
            new RestToXContentListener<>(channel)
        );
    }
    
    private String determineAction(RestRequest request) {
        String path = request.path();
        String method = request.method().name();
        
        if (path.endsWith("/status")) {
            return "get_status";
        } else if (path.endsWith("/force") && method.equals("POST")) {
            if (path.contains("/cluster/")) {
                return "force_cluster_sync";
            } else {
                return "force_sync";
            }
        } else if (path.endsWith("/strategy") && method.equals("PUT")) {
            return "update_strategy";
        } else if (path.endsWith("/conflicts")) {
            return "get_conflicts";
        } else if (path.endsWith("/cluster/status")) {
            return "get_cluster_status";
        } else if (path.endsWith("/health")) {
            return "get_health";
        }
        
        return "get_status"; // Default action
    }
}