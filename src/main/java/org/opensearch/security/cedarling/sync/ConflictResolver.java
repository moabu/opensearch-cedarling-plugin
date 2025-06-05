package org.opensearch.security.cedarling.sync;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.security.cedarling.model.PolicyStoreSnapshot;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Handles conflicts during policy store synchronization
 * 
 * Provides enterprise-grade conflict resolution strategies for scenarios like:
 * - Concurrent policy modifications
 * - Network partition scenarios
 * - Version conflicts during incremental sync
 * - Schema changes in policy definitions
 */
public class ConflictResolver {
    
    private static final Logger logger = LogManager.getLogger(ConflictResolver.class);
    
    private final ConflictResolutionStrategy strategy;
    
    public ConflictResolver(ConflictResolutionStrategy strategy) {
        this.strategy = strategy;
    }
    
    /**
     * Resolve conflicts between local and remote policy snapshots
     */
    public PolicyResolutionResult resolveConflicts(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            SynchronizationContext context
    ) {
        logger.debug("Resolving conflicts between local version {} and remote version {}", 
                    localSnapshot != null ? localSnapshot.getVersion() : "null", 
                    remoteSnapshot.getVersion());
        
        if (localSnapshot == null) {
            return PolicyResolutionResult.acceptRemote(remoteSnapshot, "No local snapshot available");
        }
        
        // Detect conflict types
        List<ConflictType> conflicts = detectConflicts(localSnapshot, remoteSnapshot);
        
        if (conflicts.isEmpty()) {
            return PolicyResolutionResult.acceptRemote(remoteSnapshot, "No conflicts detected");
        }
        
        logger.info("Detected {} conflict types: {}", conflicts.size(), conflicts);
        
        // Apply resolution strategy
        return applyResolutionStrategy(localSnapshot, remoteSnapshot, conflicts, context);
    }
    
    private List<ConflictType> detectConflicts(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot
    ) {
        List<ConflictType> conflicts = new ArrayList<>();
        
        // Version conflict
        if (!Objects.equals(localSnapshot.getVersion(), remoteSnapshot.getVersion())) {
            conflicts.add(ConflictType.VERSION_MISMATCH);
        }
        
        // Policy count discrepancy
        int localPolicyCount = localSnapshot.getPolicies().size();
        int remotePolicyCount = remoteSnapshot.getPolicies().size();
        
        if (Math.abs(localPolicyCount - remotePolicyCount) > localPolicyCount * 0.1) {
            conflicts.add(ConflictType.POLICY_COUNT_DISCREPANCY);
        }
        
        // Schema changes
        if (hasSchemaChanges(localSnapshot, remoteSnapshot)) {
            conflicts.add(ConflictType.SCHEMA_CHANGE);
        }
        
        // Policy content conflicts
        if (hasPolicyContentConflicts(localSnapshot, remoteSnapshot)) {
            conflicts.add(ConflictType.POLICY_CONTENT_CONFLICT);
        }
        
        // Timestamp conflicts
        if (hasTimestampConflicts(localSnapshot, remoteSnapshot)) {
            conflicts.add(ConflictType.TIMESTAMP_CONFLICT);
        }
        
        return conflicts;
    }
    
    private PolicyResolutionResult applyResolutionStrategy(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts,
            SynchronizationContext context
    ) {
        switch (strategy) {
            case REMOTE_WINS:
                return resolveRemoteWins(localSnapshot, remoteSnapshot, conflicts);
                
            case LOCAL_WINS:
                return resolveLocalWins(localSnapshot, remoteSnapshot, conflicts);
                
            case TIMESTAMP_BASED:
                return resolveTimestampBased(localSnapshot, remoteSnapshot, conflicts);
                
            case MERGE_POLICIES:
                return resolveMergePolicies(localSnapshot, remoteSnapshot, conflicts);
                
            case MANUAL_REVIEW:
                return resolveManualReview(localSnapshot, remoteSnapshot, conflicts);
                
            case FAIL_SAFE:
                return resolveFailSafe(localSnapshot, remoteSnapshot, conflicts);
                
            default:
                return resolveRemoteWins(localSnapshot, remoteSnapshot, conflicts);
        }
    }
    
    private PolicyResolutionResult resolveRemoteWins(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.info("Applying REMOTE_WINS strategy for conflicts: {}", conflicts);
        return PolicyResolutionResult.acceptRemote(remoteSnapshot, 
            "Remote wins strategy - accepting remote changes");
    }
    
    private PolicyResolutionResult resolveLocalWins(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.info("Applying LOCAL_WINS strategy for conflicts: {}", conflicts);
        return PolicyResolutionResult.keepLocal(localSnapshot, 
            "Local wins strategy - keeping local changes");
    }
    
    private PolicyResolutionResult resolveTimestampBased(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.info("Applying TIMESTAMP_BASED strategy for conflicts: {}", conflicts);
        
        Instant localTime = parseTimestamp(localSnapshot.getLastModified());
        Instant remoteTime = parseTimestamp(remoteSnapshot.getLastModified());
        
        if (remoteTime.isAfter(localTime)) {
            return PolicyResolutionResult.acceptRemote(remoteSnapshot, 
                "Remote snapshot is newer (" + remoteSnapshot.getLastModified() + ")");
        } else {
            return PolicyResolutionResult.keepLocal(localSnapshot, 
                "Local snapshot is newer (" + localSnapshot.getLastModified() + ")");
        }
    }
    
    private PolicyResolutionResult resolveMergePolicies(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.info("Applying MERGE_POLICIES strategy for conflicts: {}", conflicts);
        
        try {
            PolicyStoreSnapshot mergedSnapshot = mergePolicySnapshots(localSnapshot, remoteSnapshot);
            return PolicyResolutionResult.acceptMerged(mergedSnapshot, 
                "Successfully merged local and remote policies");
        } catch (Exception e) {
            logger.error("Failed to merge policies, falling back to remote", e);
            return PolicyResolutionResult.acceptRemote(remoteSnapshot, 
                "Merge failed, accepting remote: " + e.getMessage());
        }
    }
    
    private PolicyResolutionResult resolveManualReview(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.warn("Manual review required for conflicts: {}", conflicts);
        return PolicyResolutionResult.requiresManualReview(conflicts, 
            "Conflicts require manual review and resolution");
    }
    
    private PolicyResolutionResult resolveFailSafe(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot,
            List<ConflictType> conflicts
    ) {
        logger.error("Fail-safe strategy activated for conflicts: {}", conflicts);
        
        // In fail-safe mode, keep local snapshot to maintain stability
        return PolicyResolutionResult.keepLocal(localSnapshot, 
            "Fail-safe mode activated - preserving local state");
    }
    
    private PolicyStoreSnapshot mergePolicySnapshots(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot
    ) throws ConflictResolutionException {
        // Create a merged snapshot with policies from both sources
        Map<String, PolicyStoreSnapshot.CedarPolicy> localPolicies = localSnapshot.getPolicies()
            .stream()
            .collect(Collectors.toMap(
                PolicyStoreSnapshot.CedarPolicy::getId,
                policy -> policy
            ));
        
        Map<String, PolicyStoreSnapshot.CedarPolicy> remotePolicies = remoteSnapshot.getPolicies()
            .stream()
            .collect(Collectors.toMap(
                PolicyStoreSnapshot.CedarPolicy::getId,
                policy -> policy
            ));
        
        // Merge policies - remote takes precedence for conflicts
        Map<String, PolicyStoreSnapshot.CedarPolicy> mergedPolicies = new HashMap<>(localPolicies);
        
        for (Map.Entry<String, PolicyStoreSnapshot.CedarPolicy> entry : remotePolicies.entrySet()) {
            String policyId = entry.getKey();
            PolicyStoreSnapshot.CedarPolicy remotePolicy = entry.getValue();
            
            if (localPolicies.containsKey(policyId)) {
                // Conflict: choose based on timestamp or version
                PolicyStoreSnapshot.CedarPolicy localPolicy = localPolicies.get(policyId);
                
                if (shouldPreferRemotePolicy(localPolicy, remotePolicy)) {
                    mergedPolicies.put(policyId, remotePolicy);
                    logger.debug("Merged policy {} - chose remote version", policyId);
                } else {
                    logger.debug("Merged policy {} - kept local version", policyId);
                }
            } else {
                // New policy from remote
                mergedPolicies.put(policyId, remotePolicy);
                logger.debug("Merged policy {} - added from remote", policyId);
            }
        }
        
        // Create merged snapshot
        return new PolicyStoreSnapshot(
            "merged-" + remoteSnapshot.getVersion(),
            Instant.now().toString(),
            new ArrayList<>(mergedPolicies.values()),
            remoteSnapshot.getSchema(), // Use remote schema
            Map.of(
                "merge_source", "local+remote",
                "local_version", localSnapshot.getVersion(),
                "remote_version", remoteSnapshot.getVersion(),
                "merge_timestamp", Instant.now().toString()
            )
        );
    }
    
    private boolean shouldPreferRemotePolicy(
            PolicyStoreSnapshot.CedarPolicy localPolicy,
            PolicyStoreSnapshot.CedarPolicy remotePolicy
    ) {
        // Prefer remote if it has a more recent timestamp
        if (remotePolicy.getUpdatedAt() != null && localPolicy.getUpdatedAt() != null) {
            Instant remoteTime = parseTimestamp(remotePolicy.getUpdatedAt());
            Instant localTime = parseTimestamp(localPolicy.getUpdatedAt());
            return remoteTime.isAfter(localTime);
        }
        
        // If no timestamps, prefer remote by default
        return true;
    }
    
    private boolean hasSchemaChanges(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot
    ) {
        // Simple schema comparison - in production, this would be more sophisticated
        return !Objects.equals(
            localSnapshot.getSchema().toString(),
            remoteSnapshot.getSchema().toString()
        );
    }
    
    private boolean hasPolicyContentConflicts(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot
    ) {
        Set<String> localPolicyIds = localSnapshot.getPolicies().stream()
            .map(PolicyStoreSnapshot.CedarPolicy::getId)
            .collect(Collectors.toSet());
        
        Set<String> remotePolicyIds = remoteSnapshot.getPolicies().stream()
            .map(PolicyStoreSnapshot.CedarPolicy::getId)
            .collect(Collectors.toSet());
        
        // Check for significant differences in policy sets
        Set<String> onlyInLocal = new HashSet<>(localPolicyIds);
        onlyInLocal.removeAll(remotePolicyIds);
        
        Set<String> onlyInRemote = new HashSet<>(remotePolicyIds);
        onlyInRemote.removeAll(localPolicyIds);
        
        return !onlyInLocal.isEmpty() || !onlyInRemote.isEmpty();
    }
    
    private boolean hasTimestampConflicts(
            PolicyStoreSnapshot localSnapshot,
            PolicyStoreSnapshot remoteSnapshot
    ) {
        try {
            Instant localTime = parseTimestamp(localSnapshot.getLastModified());
            Instant remoteTime = parseTimestamp(remoteSnapshot.getLastModified());
            
            // Consider conflict if timestamps are very close (within 1 minute)
            long diffSeconds = Math.abs(localTime.getEpochSecond() - remoteTime.getEpochSecond());
            return diffSeconds < 60;
            
        } catch (Exception e) {
            logger.warn("Failed to parse timestamps for conflict detection", e);
            return false;
        }
    }
    
    private Instant parseTimestamp(String timestamp) {
        try {
            return Instant.parse(timestamp);
        } catch (Exception e) {
            logger.warn("Failed to parse timestamp: {}", timestamp);
            return Instant.now();
        }
    }
    
    /**
     * Types of conflicts that can occur during synchronization
     */
    public enum ConflictType {
        VERSION_MISMATCH,
        POLICY_COUNT_DISCREPANCY,
        SCHEMA_CHANGE,
        POLICY_CONTENT_CONFLICT,
        TIMESTAMP_CONFLICT
    }
    
    /**
     * Strategies for resolving conflicts
     */
    public enum ConflictResolutionStrategy {
        REMOTE_WINS,      // Always accept remote changes
        LOCAL_WINS,       // Always keep local changes
        TIMESTAMP_BASED,  // Use timestamps to determine winner
        MERGE_POLICIES,   // Attempt to merge both sets of policies
        MANUAL_REVIEW,    // Flag for manual resolution
        FAIL_SAFE         // Conservative approach - keep local on conflicts
    }
    
    /**
     * Exception thrown when conflict resolution fails
     */
    public static class ConflictResolutionException extends Exception {
        public ConflictResolutionException(String message) {
            super(message);
        }
        
        public ConflictResolutionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}