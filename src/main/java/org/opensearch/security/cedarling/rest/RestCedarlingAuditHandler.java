package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingAuditAction;
import org.opensearch.security.cedarling.action.CedarlingAuditRequest;

import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for audit and analytics operations
 * 
 * Endpoints:
 * GET /_cedarling/audit/metrics - Get current audit metrics
 * GET /_cedarling/audit/analytics - Get comprehensive analytics report
 * POST /_cedarling/audit/reset - Reset audit metrics
 */
public class RestCedarlingAuditHandler extends BaseRestHandler {

    @Override
    public String getName() {
        return "cedarling_audit_handler";
    }

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_cedarling/audit/metrics"),
            new Route(GET, "/_cedarling/audit/analytics"),
            new Route(POST, "/_cedarling/audit/reset")
        ));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        String action = determineAction(request);
        CedarlingAuditRequest auditRequest = new CedarlingAuditRequest(action);
        
        return channel -> client.execute(
            CedarlingAuditAction.INSTANCE,
            auditRequest,
            new RestToXContentListener<>(channel)
        );
    }
    
    private String determineAction(RestRequest request) {
        String path = request.path();
        
        if (path.endsWith("/metrics")) {
            return "metrics";
        } else if (path.endsWith("/analytics")) {
            return "analytics";
        } else if (path.endsWith("/reset")) {
            return "reset";
        }
        
        return "metrics";
    }
}