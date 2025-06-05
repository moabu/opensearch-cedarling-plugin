package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionType;

/**
 * Action type for Cedarling policy management
 */
public class CedarlingPolicyAction extends ActionType<CedarlingPolicyResponse> {
    
    public static final CedarlingPolicyAction INSTANCE = new CedarlingPolicyAction();
    public static final String NAME = "cluster:admin/cedarling/policy";
    
    private CedarlingPolicyAction() {
        super(NAME, CedarlingPolicyResponse::new);
    }
}