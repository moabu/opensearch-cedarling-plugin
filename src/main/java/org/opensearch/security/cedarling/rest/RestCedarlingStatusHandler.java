package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.cedarling.service.CedarlingService;

import java.io.IOException;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * REST handler for Cedarling service status
 * 
 * Endpoint: GET /_plugins/_cedarling/status
 */
public class RestCedarlingStatusHandler extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return unmodifiableList(asList(
            new Route(GET, "/_plugins/_cedarling/status")
        ));
    }

    @Override
    public String getName() {
        return "cedarling_status_handler";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            try {
                // Get Cedarling service from client
                CedarlingService cedarlingService = client.getLocalNodeClient().injector().getInstance(CedarlingService.class);
                
                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("enabled", cedarlingService.isEnabled());
                builder.field("endpoint", cedarlingService.getEndpoint());
                builder.field("policy_store_id", cedarlingService.getPolicyStoreId());
                
                // Check health asynchronously
                cedarlingService.checkHealth().whenComplete((healthy, throwable) -> {
                    try {
                        builder.field("healthy", healthy != null ? healthy : false);
                        
                        // Get policy store status
                        cedarlingService.getPolicyStoreStatus().whenComplete((status, statusThrowable) -> {
                            try {
                                if (status != null) {
                                    builder.field("policy_store_active", status.isActive());
                                    builder.field("policy_count", status.getPolicyCount());
                                    builder.field("last_updated", status.getLastUpdated());
                                } else {
                                    builder.field("policy_store_active", false);
                                }
                                
                                builder.endObject();
                                channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
                            } catch (IOException e) {
                                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                                    "Error building response: " + e.getMessage()));
                            }
                        });
                        
                    } catch (Exception e) {
                        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                            "Error checking service status: " + e.getMessage()));
                    }
                });
                
            } catch (Exception e) {
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error getting Cedarling service: " + e.getMessage()));
            }
        };
    }
}