package org.opensearch.security.cedarling.sync;

import org.opensearch.security.cedarling.model.PolicyStoreSnapshot;

import java.util.List;

/**
 * Result of policy conflict resolution during synchronization
 * 
 * Encapsulates the decision made by the conflict resolver and provides
 * context for the synchronization engine to proceed appropriately.
 */
public class PolicyResolutionResult {
    
    private final ResolutionAction action;
    private final PolicyStoreSnapshot resolvedSnapshot;
    private final String reason;
    private final List<ConflictResolver.ConflictType> unresolvedConflicts;
    private final boolean requiresManualIntervention;
    
    private PolicyResolutionResult(
            ResolutionAction action,
            PolicyStoreSnapshot resolvedSnapshot,
            String reason,
            List<ConflictResolver.ConflictType> unresolvedConflicts,
            boolean requiresManualIntervention
    ) {
        this.action = action;
        this.resolvedSnapshot = resolvedSnapshot;
        this.reason = reason;
        this.unresolvedConflicts = unresolvedConflicts;
        this.requiresManualIntervention = requiresManualIntervention;
    }
    
    /**
     * Accept the remote snapshot as the resolution
     */
    public static PolicyResolutionResult acceptRemote(PolicyStoreSnapshot remoteSnapshot, String reason) {
        return new PolicyResolutionResult(
            ResolutionAction.ACCEPT_REMOTE,
            remoteSnapshot,
            reason,
            List.of(),
            false
        );
    }
    
    /**
     * Keep the local snapshot as the resolution
     */
    public static PolicyResolutionResult keepLocal(PolicyStoreSnapshot localSnapshot, String reason) {
        return new PolicyResolutionResult(
            ResolutionAction.KEEP_LOCAL,
            localSnapshot,
            reason,
            List.of(),
            false
        );
    }
    
    /**
     * Accept a merged snapshot as the resolution
     */
    public static PolicyResolutionResult acceptMerged(PolicyStoreSnapshot mergedSnapshot, String reason) {
        return new PolicyResolutionResult(
            ResolutionAction.ACCEPT_MERGED,
            mergedSnapshot,
            reason,
            List.of(),
            false
        );
    }
    
    /**
     * Flag conflicts that require manual review
     */
    public static PolicyResolutionResult requiresManualReview(
            List<ConflictResolver.ConflictType> conflicts,
            String reason
    ) {
        return new PolicyResolutionResult(
            ResolutionAction.MANUAL_REVIEW,
            null,
            reason,
            conflicts,
            true
        );
    }
    
    /**
     * Abort synchronization due to unresolvable conflicts
     */
    public static PolicyResolutionResult abortSync(String reason) {
        return new PolicyResolutionResult(
            ResolutionAction.ABORT_SYNC,
            null,
            reason,
            List.of(),
            false
        );
    }
    
    // Getters
    public ResolutionAction getAction() {
        return action;
    }
    
    public PolicyStoreSnapshot getResolvedSnapshot() {
        return resolvedSnapshot;
    }
    
    public String getReason() {
        return reason;
    }
    
    public List<ConflictResolver.ConflictType> getUnresolvedConflicts() {
        return unresolvedConflicts;
    }
    
    public boolean requiresManualIntervention() {
        return requiresManualIntervention;
    }
    
    /**
     * Check if the resolution was successful
     */
    public boolean isSuccessful() {
        return action != ResolutionAction.ABORT_SYNC && action != ResolutionAction.MANUAL_REVIEW;
    }
    
    /**
     * Check if synchronization should proceed
     */
    public boolean shouldProceedWithSync() {
        return action == ResolutionAction.ACCEPT_REMOTE || 
               action == ResolutionAction.ACCEPT_MERGED;
    }
    
    /**
     * Check if local snapshot should be preserved
     */
    public boolean shouldKeepLocal() {
        return action == ResolutionAction.KEEP_LOCAL;
    }
    
    @Override
    public String toString() {
        return "PolicyResolutionResult{" +
                "action=" + action +
                ", reason='" + reason + '\'' +
                ", requiresManualIntervention=" + requiresManualIntervention +
                ", unresolvedConflicts=" + unresolvedConflicts +
                '}';
    }
    
    /**
     * Actions that can be taken as a result of conflict resolution
     */
    public enum ResolutionAction {
        ACCEPT_REMOTE,    // Use the remote snapshot
        KEEP_LOCAL,       // Keep the current local snapshot
        ACCEPT_MERGED,    // Use a merged snapshot
        MANUAL_REVIEW,    // Flag for manual administrator review
        ABORT_SYNC        // Cancel synchronization operation
    }
}