package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.security.cedarling.action.CedarlingPolicyAction;
import org.opensearch.security.cedarling.action.CedarlingPolicyRequest;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for Cedarling policy management
 * 
 * Endpoints:
 * - GET /_plugins/_cedarling/policies - List policies
 * - GET /_plugins/_cedarling/policies/{id} - Get specific policy
 * - POST /_plugins/_cedarling/policies - Create policy
 * - PUT /_plugins/_cedarling/policies/{id} - Update policy
 * - DELETE /_plugins/_cedarling/policies/{id} - Delete policy
 */
public class RestCedarlingPolicyHandler extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_plugins/_cedarling/policies"),
            new Route(GET, "/_plugins/_cedarling/policies/{policy_id}"),
            new Route(POST, "/_plugins/_cedarling/policies"),
            new Route(PUT, "/_plugins/_cedarling/policies/{policy_id}"),
            new Route(DELETE, "/_plugins/_cedarling/policies/{policy_id}")
        ));
    }

    @Override
    public String getName() {
        return "cedarling_policy_handler";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        CedarlingPolicyRequest policyRequest = new CedarlingPolicyRequest();
        
        // Set operation type based on HTTP method
        switch (request.method()) {
            case GET:
                policyRequest.setOperation("list");
                break;
            case POST:
                policyRequest.setOperation("create");
                break;
            case PUT:
                policyRequest.setOperation("update");
                break;
            case DELETE:
                policyRequest.setOperation("delete");
                break;
        }
        
        // Extract policy ID from path if present
        String policyId = request.param("policy_id");
        if (policyId != null) {
            policyRequest.setPolicyId(policyId);
            if (request.method() == GET) {
                policyRequest.setOperation("get");
            }
        }
        
        // Parse request body for create/update operations
        if (request.hasContent() && (request.method() == POST || request.method() == PUT)) {
            try (XContentParser parser = request.contentParser()) {
                Map<String, Object> body = parser.map();
                policyRequest.setPolicyContent((String) body.get("policy"));
                policyRequest.setDescription((String) body.get("description"));
                if (request.method() == POST && body.containsKey("id")) {
                    policyRequest.setPolicyId((String) body.get("id"));
                }
            }
        }
        
        return channel -> client.execute(CedarlingPolicyAction.INSTANCE, policyRequest, new RestToXContentListener<>(channel));
    }
}