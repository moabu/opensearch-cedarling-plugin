package org.opensearch.security.cedarling.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.security.cedarling.model.AuthorizationRequest;
import org.opensearch.security.cedarling.model.AuthorizationResponse;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import org.opensearch.core.action.ActionListener;

/**
 * Transport action for handling Cedarling authorization requests
 */
public class TransportCedarlingAuthorizationAction extends HandledTransportAction<CedarlingAuthorizationRequest, CedarlingAuthorizationResponse> {

    private final CedarlingService cedarlingService;

    @Inject
    public TransportCedarlingAuthorizationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            CedarlingService cedarlingService
    ) {
        super(CedarlingAuthorizationAction.NAME, transportService, actionFilters, CedarlingAuthorizationRequest::new);
        this.cedarlingService = cedarlingService;
    }

    @Override
    protected void doExecute(Task task, CedarlingAuthorizationRequest request, ActionListener<CedarlingAuthorizationResponse> listener) {
        
        // Build authorization request for Cedarling service
        AuthorizationRequest authRequest = AuthorizationRequest.builder()
            .principal(request.getPrincipalType(), request.getPrincipalId())
            .action(request.getAction())
            .resource(request.getResourceType(), request.getResourceId())
            .tenant(request.getTenant())
            .account(request.getAccount())
            .roles(request.getRoles())
            .context(request.getContext())
            .build();

        // Make async authorization request to Cedarling
        cedarlingService.authorize(authRequest)
            .whenComplete((response, throwable) -> {
                if (throwable != null) {
                    listener.onFailure(new RuntimeException("Authorization request failed", throwable));
                } else {
                    CedarlingAuthorizationResponse authResponse = new CedarlingAuthorizationResponse(
                        response.isAllowed(),
                        response.getReason(),
                        response.getDiagnostics() != null ? response.getDiagnostics().toString() : null
                    );
                    listener.onResponse(authResponse);
                }
            });
    }
}