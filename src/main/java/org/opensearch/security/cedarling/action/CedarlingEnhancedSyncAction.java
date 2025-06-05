package org.opensearch.security.cedarling.action;

import org.opensearch.action.ActionType;

/**
 * Action for enhanced policy store synchronization operations
 * 
 * Supports intelligent synchronization strategies, conflict resolution,
 * and distributed coordination across OpenSearch clusters.
 */
public class CedarlingEnhancedSyncAction extends ActionType<CedarlingEnhancedSyncResponse> {
    
    public static final CedarlingEnhancedSyncAction INSTANCE = new CedarlingEnhancedSyncAction();
    public static final String NAME = "cluster:admin/cedarling/sync/enhanced";
    
    private CedarlingEnhancedSyncAction() {
        super(NAME, CedarlingEnhancedSyncResponse::new);
    }
}