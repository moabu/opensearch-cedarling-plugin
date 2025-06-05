package org.opensearch.security.cedarling.action;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer.SynchronizationStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * Transport handler for policy synchronization operations
 */
public class TransportCedarlingPolicySyncAction extends HandledTransportAction<CedarlingPolicySyncRequest, CedarlingPolicySyncResponse> {
    
    private final CedarlingService cedarlingService;
    private final PolicyStoreSynchronizer policyStoreSynchronizer;
    
    @Inject
    public TransportCedarlingPolicySyncAction(
            TransportService transportService,
            ActionFilters actionFilters,
            CedarlingService cedarlingService,
            PolicyStoreSynchronizer policyStoreSynchronizer
    ) {
        super(CedarlingPolicySyncAction.NAME, transportService, actionFilters, CedarlingPolicySyncRequest::new);
        this.cedarlingService = cedarlingService;
        this.policyStoreSynchronizer = policyStoreSynchronizer;
    }
    
    @Override
    protected void doExecute(Task task, CedarlingPolicySyncRequest request, ActionListener<CedarlingPolicySyncResponse> listener) {
        String action = request.getAction();
        
        try {
            switch (action) {
                case "status":
                    handleStatusRequest(listener);
                    break;
                case "force_sync":
                    handleForceSyncRequest(listener);
                    break;
                default:
                    listener.onResponse(new CedarlingPolicySyncResponse(
                        action, 
                        false, 
                        "Unknown action: " + action, 
                        null
                    ));
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }
    
    private void handleStatusRequest(ActionListener<CedarlingPolicySyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(new CedarlingPolicySyncResponse(
                "status",
                true,
                "Policy synchronization is disabled",
                null
            ));
            return;
        }
        
        SynchronizationStatus status = policyStoreSynchronizer.getStatus();
        listener.onResponse(new CedarlingPolicySyncResponse(
            "status",
            true,
            "Synchronization status retrieved successfully",
            status
        ));
    }
    
    private void handleForceSyncRequest(ActionListener<CedarlingPolicySyncResponse> listener) {
        if (policyStoreSynchronizer == null) {
            listener.onResponse(new CedarlingPolicySyncResponse(
                "force_sync",
                false,
                "Policy synchronization is disabled",
                null
            ));
            return;
        }
        
        // Force a synchronization check
        policyStoreSynchronizer.forceSyncCheck().whenComplete((updated, throwable) -> {
            if (throwable != null) {
                listener.onResponse(new CedarlingPolicySyncResponse(
                    "force_sync",
                    false,
                    "Synchronization failed: " + throwable.getMessage(),
                    policyStoreSynchronizer.getStatus()
                ));
            } else {
                String message = updated ? 
                    "Policy store synchronized successfully - policies updated" :
                    "Policy store is already up to date";
                    
                listener.onResponse(new CedarlingPolicySyncResponse(
                    "force_sync",
                    true,
                    message,
                    policyStoreSynchronizer.getStatus()
                ));
            }
        });
    }
}