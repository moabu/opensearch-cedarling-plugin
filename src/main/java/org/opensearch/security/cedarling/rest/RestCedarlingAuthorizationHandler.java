package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingAuthorizationAction;
import org.opensearch.security.cedarling.action.CedarlingAuthorizationRequest;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for Cedarling authorization requests
 * 
 * Endpoint: POST /_plugins/_cedarling/authorize
 */
public class RestCedarlingAuthorizationHandler extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(POST, "/_plugins/_cedarling/authorize")
        ));
    }

    @Override
    public String getName() {
        return "cedarling_authorization_handler";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        CedarlingAuthorizationRequest authRequest = new CedarlingAuthorizationRequest();
        
        if (request.hasContent()) {
            try (XContentParser parser = request.contentParser()) {
                Map<String, Object> body = parser.map();
                
                // Extract principal information
                Map<String, Object> principal = (Map<String, Object>) body.get("principal");
                if (principal != null) {
                    authRequest.setPrincipalType((String) principal.get("type"));
                    authRequest.setPrincipalId((String) principal.get("id"));
                    authRequest.setTenant((String) principal.get("tenant"));
                    authRequest.setAccount((String) principal.get("account"));
                    authRequest.setRoles((List<String>) principal.get("roles"));
                }
                
                // Extract action
                authRequest.setAction((String) body.get("action"));
                
                // Extract resource information
                Map<String, Object> resource = (Map<String, Object>) body.get("resource");
                if (resource != null) {
                    authRequest.setResourceType((String) resource.get("type"));
                    authRequest.setResourceId((String) resource.get("id"));
                }
                
                // Extract context
                authRequest.setContext((Map<String, Object>) body.get("context"));
            }
        }
        
        return channel -> client.execute(CedarlingAuthorizationAction.INSTANCE, authRequest, new RestToXContentListener<>(channel));
    }
}