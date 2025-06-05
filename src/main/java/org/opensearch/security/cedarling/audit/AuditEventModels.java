/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.audit;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Event models for comprehensive audit logging
 */
public class AuditEventModels {
    
    /**
     * Authorization decision event containing all context for security decisions
     */
    public static class AuthorizationDecisionEvent {
        private final String decision;
        private final String action;
        private final String resource;
        private final String principal;
        private final List<String> policiesEvaluated;
        private final double responseTimeMs;
        private final String reason;
        private final Map<String, Object> tokenInfo;
        private final String clientIp;
        private final String userAgent;
        private final String requestId;
        private final String sessionId;
        private final String clusterNode;
        private final Instant timestamp;
        
        public AuthorizationDecisionEvent(String decision, String action, String resource, 
                                        String principal, List<String> policiesEvaluated, 
                                        double responseTimeMs, String reason, 
                                        Map<String, Object> tokenInfo, String clientIp, 
                                        String userAgent, String requestId, String sessionId, 
                                        String clusterNode) {
            this.decision = decision;
            this.action = action;
            this.resource = resource;
            this.principal = principal;
            this.policiesEvaluated = policiesEvaluated;
            this.responseTimeMs = responseTimeMs;
            this.reason = reason;
            this.tokenInfo = tokenInfo;
            this.clientIp = clientIp;
            this.userAgent = userAgent;
            this.requestId = requestId;
            this.sessionId = sessionId;
            this.clusterNode = clusterNode;
            this.timestamp = Instant.now();
        }
        
        // Getters
        public String getDecision() { return decision; }
        public String getAction() { return action; }
        public String getResource() { return resource; }
        public String getPrincipal() { return principal; }
        public List<String> getPoliciesEvaluated() { return policiesEvaluated; }
        public double getResponseTimeMs() { return responseTimeMs; }
        public String getReason() { return reason; }
        public Map<String, Object> getTokenInfo() { return tokenInfo; }
        public String getClientIp() { return clientIp; }
        public String getUserAgent() { return userAgent; }
        public String getRequestId() { return requestId; }
        public String getSessionId() { return sessionId; }
        public String getClusterNode() { return clusterNode; }
        public Instant getTimestamp() { return timestamp; }
    }
    
    /**
     * Policy synchronization event for tracking policy updates
     */
    public static class PolicySyncEvent {
        private final String status;
        private final List<String> policiesUpdated;
        private final long durationMs;
        private final String source;
        private final String errorMessage;
        private final String clusterNode;
        private final Instant timestamp;
        
        public PolicySyncEvent(String status, List<String> policiesUpdated, long durationMs, 
                             String source, String errorMessage, String clusterNode) {
            this.status = status;
            this.policiesUpdated = policiesUpdated;
            this.durationMs = durationMs;
            this.source = source;
            this.errorMessage = errorMessage;
            this.clusterNode = clusterNode;
            this.timestamp = Instant.now();
        }
        
        // Getters
        public String getStatus() { return status; }
        public List<String> getPoliciesUpdated() { return policiesUpdated; }
        public long getDurationMs() { return durationMs; }
        public String getSource() { return source; }
        public String getErrorMessage() { return errorMessage; }
        public String getClusterNode() { return clusterNode; }
        public Instant getTimestamp() { return timestamp; }
    }
    
    /**
     * Configuration change event for tracking system modifications
     */
    public static class ConfigurationChangeEvent {
        private final String key;
        private final String oldValue;
        private final String newValue;
        private final String changedBy;
        private final String clusterNode;
        private final Instant timestamp;
        
        public ConfigurationChangeEvent(String key, String oldValue, String newValue, 
                                      String changedBy, String clusterNode) {
            this.key = key;
            this.oldValue = oldValue;
            this.newValue = newValue;
            this.changedBy = changedBy;
            this.clusterNode = clusterNode;
            this.timestamp = Instant.now();
        }
        
        // Getters
        public String getKey() { return key; }
        public String getOldValue() { return oldValue; }
        public String getNewValue() { return newValue; }
        public String getChangedBy() { return changedBy; }
        public String getClusterNode() { return clusterNode; }
        public Instant getTimestamp() { return timestamp; }
    }
    
    /**
     * Performance metrics event for system monitoring
     */
    public static class PerformanceEvent {
        private final double responseTimeMs;
        private final double memoryUsageMb;
        private final double cpuUsagePercent;
        private final int activeConnections;
        private final int queueSize;
        private final double throughputPerSecond;
        private final String clusterNode;
        private final Instant timestamp;
        
        public PerformanceEvent(double responseTimeMs, double memoryUsageMb, 
                               double cpuUsagePercent, int activeConnections, 
                               int queueSize, double throughputPerSecond, 
                               String clusterNode) {
            this.responseTimeMs = responseTimeMs;
            this.memoryUsageMb = memoryUsageMb;
            this.cpuUsagePercent = cpuUsagePercent;
            this.activeConnections = activeConnections;
            this.queueSize = queueSize;
            this.throughputPerSecond = throughputPerSecond;
            this.clusterNode = clusterNode;
            this.timestamp = Instant.now();
        }
        
        // Getters
        public double getResponseTimeMs() { return responseTimeMs; }
        public double getMemoryUsageMb() { return memoryUsageMb; }
        public double getCpuUsagePercent() { return cpuUsagePercent; }
        public int getActiveConnections() { return activeConnections; }
        public int getQueueSize() { return queueSize; }
        public double getThroughputPerSecond() { return throughputPerSecond; }
        public String getClusterNode() { return clusterNode; }
        public Instant getTimestamp() { return timestamp; }
    }
}