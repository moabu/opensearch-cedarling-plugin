package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionType;

/**
 * Action for policy synchronization operations
 */
public class CedarlingPolicySyncAction extends ActionType<CedarlingPolicySyncResponse> {
    
    public static final CedarlingPolicySyncAction INSTANCE = new CedarlingPolicySyncAction();
    public static final String NAME = "cluster:admin/cedarling/policy_sync";
    
    private CedarlingPolicySyncAction() {
        super(NAME, CedarlingPolicySyncResponse::new);
    }
}