package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionType;

/**
 * Action type for Cedarling authorization requests
 */
public class CedarlingAuthorizationAction extends ActionType<CedarlingAuthorizationResponse> {
    
    public static final CedarlingAuthorizationAction INSTANCE = new CedarlingAuthorizationAction();
    public static final String NAME = "cluster:admin/cedarling/authorize";
    
    private CedarlingAuthorizationAction() {
        super(NAME, CedarlingAuthorizationResponse::new);
    }
}