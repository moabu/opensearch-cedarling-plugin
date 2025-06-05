package org.opensearch.security.cedarling.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingPolicySyncStatusAction;
import org.opensearch.security.cedarling.action.CedarlingPolicySyncStatusRequest;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * REST handler for comprehensive policy store synchronization status
 * 
 * Endpoints:
 * GET /_plugins/_cedarling/sync/status - Get detailed sync status
 * GET /_plugins/_cedarling/sync/cluster - Get cluster-wide sync status  
 * GET /_plugins/_cedarling/sync/health - Get sync health assessment
 */
public class RestCedarlingSync StatusHandler extends BaseRestHandler {
    
    private static final Logger logger = LogManager.getLogger(RestCedarlingSync StatusHandler.class);
    
    @Override
    public String getName() {
        return "cedarling_sync_status_handler";
    }
    
    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, "/_plugins/_cedarling/sync/status"),
            new Route(GET, "/_plugins/_cedarling/sync/cluster"),
            new Route(GET, "/_plugins/_cedarling/sync/health")
        );
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String endpoint = request.path();
        String statusType;
        
        if (endpoint.endsWith("/cluster")) {
            statusType = "cluster";
        } else if (endpoint.endsWith("/health")) {
            statusType = "health";  
        } else {
            statusType = "detailed";
        }
        
        CedarlingPolicySyncStatusRequest syncStatusRequest = 
            new CedarlingPolicySyncStatusRequest(statusType);
            
        return channel -> client.execute(
            CedarlingPolicySyncStatusAction.INSTANCE,
            syncStatusRequest,
            new RestToXContentListener<>(channel)
        );
    }
}