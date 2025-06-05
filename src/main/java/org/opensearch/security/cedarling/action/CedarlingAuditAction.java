package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionType;

/**
 * Action for audit and analytics operations
 */
public class CedarlingAuditAction extends ActionType<CedarlingAuditResponse> {
    
    public static final CedarlingAuditAction INSTANCE = new CedarlingAuditAction();
    public static final String NAME = "cluster:admin/cedarling/audit";
    
    private CedarlingAuditAction() {
        super(NAME, CedarlingAuditResponse::new);
    }
}