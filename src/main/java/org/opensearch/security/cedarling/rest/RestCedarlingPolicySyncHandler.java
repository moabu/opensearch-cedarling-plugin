package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingPolicySyncAction;
import org.opensearch.security.cedarling.action.CedarlingPolicySyncRequest;

import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for policy synchronization operations
 * 
 * Endpoints:
 * GET /_cedarling/policy_sync/status - Get synchronization status
 * POST /_cedarling/policy_sync/force - Force immediate synchronization
 */
public class RestCedarlingPolicySyncHandler extends BaseRestHandler {

    @Override
    public String getName() {
        return "cedarling_policy_sync_handler";
    }

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_cedarling/policy_sync/status"),
            new Route(POST, "/_cedarling/policy_sync/force")
        ));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String action = determineAction(request);
        CedarlingPolicySyncRequest syncRequest = new CedarlingPolicySyncRequest(action);
        
        return channel -> client.execute(
            CedarlingPolicySyncAction.INSTANCE,
            syncRequest,
            new RestToXContentListener<>(channel)
        );
    }
    
    private String determineAction(RestRequest request) {
        String path = request.path();
        
        if (path.endsWith("/status")) {
            return "status";
        } else if (path.endsWith("/force")) {
            return "force_sync";
        }
        
        return "status";
    }
}