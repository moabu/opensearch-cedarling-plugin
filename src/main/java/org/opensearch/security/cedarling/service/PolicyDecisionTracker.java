/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.service;

import org.opensearch.common.component.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for tracking and analyzing Cedarling policy decisions
 * Provides real-time metrics and analytics for the dashboard
 */
public class PolicyDecisionTracker extends AbstractLifecycleComponent {
    
    private static final int MAX_DECISIONS = 1000;
    
    private final Queue<PolicyDecision> recentDecisions;
    private final Map<String, PolicyStats> policyStatistics;
    private final Map<String, UserStats> userStatistics;
    private final Map<String, ResourceStats> resourceStatistics;
    private final AtomicLong totalDecisions;
    private final AtomicLong allowedDecisions;
    
    public PolicyDecisionTracker(Settings settings) {
        super();
        this.recentDecisions = new ConcurrentLinkedQueue<>();
        this.policyStatistics = new ConcurrentHashMap<>();
        this.userStatistics = new ConcurrentHashMap<>();
        this.resourceStatistics = new ConcurrentHashMap<>();
        this.totalDecisions = new AtomicLong(0);
        this.allowedDecisions = new AtomicLong(0);
    }
    
    /**
     * Records a policy decision for tracking and analytics
     */
    public void recordDecision(Map<String, Object> decisionData) {
        PolicyDecision decision = new PolicyDecision(
            (String) decisionData.get("decision"),
            (String) decisionData.get("action"),
            (String) decisionData.get("resource"),
            (String) decisionData.get("user"),
            (List<String>) decisionData.getOrDefault("policies_evaluated", Collections.emptyList()),
            ((Number) decisionData.getOrDefault("response_time_ms", 0.0)).doubleValue(),
            (String) decisionData.getOrDefault("reason", ""),
            Instant.now()
        );
        
        // Add to recent decisions queue
        recentDecisions.offer(decision);
        if (recentDecisions.size() > MAX_DECISIONS) {
            recentDecisions.poll();
        }
        
        // Update statistics
        updateStatistics(decision);
        
        totalDecisions.incrementAndGet();
        if ("ALLOW".equals(decision.getDecision())) {
            allowedDecisions.incrementAndGet();
        }
    }
    
    private void updateStatistics(PolicyDecision decision) {
        String decisionType = decision.getDecision();
        
        // Update policy statistics
        for (String policy : decision.getPoliciesEvaluated()) {
            policyStatistics.computeIfAbsent(policy, k -> new PolicyStats())
                .increment(decisionType);
        }
        
        // Update user statistics
        userStatistics.computeIfAbsent(decision.getUser(), k -> new UserStats())
            .incrementRequest(decisionType);
        
        // Update resource statistics
        resourceStatistics.computeIfAbsent(decision.getResource(), k -> new ResourceStats())
            .incrementAccess(decisionType);
    }
    
    /**
     * Gets comprehensive dashboard data
     */
    public Map<String, Object> getDashboardData() {
        Map<String, Object> data = new HashMap<>();
        
        long total = totalDecisions.get();
        long allowed = allowedDecisions.get();
        
        data.put("total_decisions", total);
        data.put("allow_count", allowed);
        data.put("deny_count", total - allowed);
        data.put("allow_rate", total > 0 ? Math.round((allowed * 100.0 / total) * 10.0) / 10.0 : 0.0);
        
        // Calculate average response time
        double avgResponseTime = recentDecisions.stream()
            .mapToDouble(PolicyDecision::getResponseTimeMs)
            .average()
            .orElse(0.0);
        data.put("avg_response_time_ms", Math.round(avgResponseTime * 100.0) / 100.0);
        
        // Recent decisions
        List<Map<String, Object>> recentDecisionsList = new ArrayList<>();
        for (PolicyDecision decision : recentDecisions) {
            recentDecisionsList.add(decision.toMap());
        }
        data.put("recent_decisions", recentDecisionsList);
        
        // Statistics
        data.put("policy_statistics", convertPolicyStats());
        data.put("user_statistics", convertUserStats());
        data.put("resource_statistics", convertResourceStats());
        data.put("active_policies", policyStatistics.size());
        
        return data;
    }
    
    private Map<String, Map<String, Object>> convertPolicyStats() {
        Map<String, Map<String, Object>> result = new HashMap<>();
        for (Map.Entry<String, PolicyStats> entry : policyStatistics.entrySet()) {
            PolicyStats stats = entry.getValue();
            Map<String, Object> statsMap = new HashMap<>();
            statsMap.put("allow", stats.getAllowCount());
            statsMap.put("deny", stats.getDenyCount());
            statsMap.put("total", stats.getTotalCount());
            result.put(entry.getKey(), statsMap);
        }
        return result;
    }
    
    private Map<String, Map<String, Object>> convertUserStats() {
        Map<String, Map<String, Object>> result = new HashMap<>();
        for (Map.Entry<String, UserStats> entry : userStatistics.entrySet()) {
            UserStats stats = entry.getValue();
            Map<String, Object> statsMap = new HashMap<>();
            statsMap.put("requests", stats.getTotalRequests());
            statsMap.put("allowed", stats.getAllowedRequests());
            statsMap.put("denied", stats.getDeniedRequests());
            result.put(entry.getKey(), statsMap);
        }
        return result;
    }
    
    private Map<String, Map<String, Object>> convertResourceStats() {
        Map<String, Map<String, Object>> result = new HashMap<>();
        for (Map.Entry<String, ResourceStats> entry : resourceStatistics.entrySet()) {
            ResourceStats stats = entry.getValue();
            Map<String, Object> statsMap = new HashMap<>();
            statsMap.put("access_attempts", stats.getAccessAttempts());
            statsMap.put("successful", stats.getSuccessfulAccess());
            result.put(entry.getKey(), statsMap);
        }
        return result;
    }
    
    public long getTotalDecisions() {
        return totalDecisions.get();
    }
    
    public double getAllowRate() {
        long total = totalDecisions.get();
        return total > 0 ? (allowedDecisions.get() * 100.0 / total) : 0.0;
    }
    
    public Map<String, Map<String, Object>> getPolicyStatistics() {
        return convertPolicyStats();
    }
    
    public Map<String, Map<String, Object>> getUserStatistics() {
        return convertUserStats();
    }
    
    public Map<String, Map<String, Object>> getResourceStatistics() {
        return convertResourceStats();
    }
    
    @Override
    protected void doStart() {
        // Initialize tracking service
    }
    
    @Override
    protected void doStop() {
        // Cleanup resources
    }
    
    @Override
    protected void doClose() {
        recentDecisions.clear();
        policyStatistics.clear();
        userStatistics.clear();
        resourceStatistics.clear();
    }
    
    // Inner classes for statistics tracking
    
    private static class PolicyDecision {
        private final String decision;
        private final String action;
        private final String resource;
        private final String user;
        private final List<String> policiesEvaluated;
        private final double responseTimeMs;
        private final String reason;
        private final Instant timestamp;
        
        public PolicyDecision(String decision, String action, String resource, String user,
                            List<String> policiesEvaluated, double responseTimeMs, String reason, Instant timestamp) {
            this.decision = decision;
            this.action = action;
            this.resource = resource;
            this.user = user;
            this.policiesEvaluated = new ArrayList<>(policiesEvaluated);
            this.responseTimeMs = responseTimeMs;
            this.reason = reason;
            this.timestamp = timestamp;
        }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("decision", decision);
            map.put("action", action);
            map.put("resource", resource);
            map.put("user", user);
            map.put("policies", policiesEvaluated);
            map.put("response_time_ms", responseTimeMs);
            map.put("reason", reason);
            map.put("timestamp", timestamp.toString());
            return map;
        }
        
        // Getters
        public String getDecision() { return decision; }
        public String getAction() { return action; }
        public String getResource() { return resource; }
        public String getUser() { return user; }
        public List<String> getPoliciesEvaluated() { return policiesEvaluated; }
        public double getResponseTimeMs() { return responseTimeMs; }
        public String getReason() { return reason; }
        public Instant getTimestamp() { return timestamp; }
    }
    
    private static class PolicyStats {
        private final AtomicLong allowCount = new AtomicLong(0);
        private final AtomicLong denyCount = new AtomicLong(0);
        
        public void increment(String decision) {
            if ("ALLOW".equals(decision)) {
                allowCount.incrementAndGet();
            } else {
                denyCount.incrementAndGet();
            }
        }
        
        public long getAllowCount() { return allowCount.get(); }
        public long getDenyCount() { return denyCount.get(); }
        public long getTotalCount() { return allowCount.get() + denyCount.get(); }
    }
    
    private static class UserStats {
        private final AtomicLong totalRequests = new AtomicLong(0);
        private final AtomicLong allowedRequests = new AtomicLong(0);
        private final AtomicLong deniedRequests = new AtomicLong(0);
        
        public void incrementRequest(String decision) {
            totalRequests.incrementAndGet();
            if ("ALLOW".equals(decision)) {
                allowedRequests.incrementAndGet();
            } else {
                deniedRequests.incrementAndGet();
            }
        }
        
        public long getTotalRequests() { return totalRequests.get(); }
        public long getAllowedRequests() { return allowedRequests.get(); }
        public long getDeniedRequests() { return deniedRequests.get(); }
    }
    
    private static class ResourceStats {
        private final AtomicLong accessAttempts = new AtomicLong(0);
        private final AtomicLong successfulAccess = new AtomicLong(0);
        
        public void incrementAccess(String decision) {
            accessAttempts.incrementAndGet();
            if ("ALLOW".equals(decision)) {
                successfulAccess.incrementAndGet();
            }
        }
        
        public long getAccessAttempts() { return accessAttempts.get(); }
        public long getSuccessfulAccess() { return successfulAccess.get(); }
    }
}