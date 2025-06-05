package org.opensearch.security.cedarling.audit;

import java.time.Instant;
import java.util.Map;

/**
 * Comprehensive analytics report containing security insights and metrics
 * 
 * Provides detailed analysis of authorization patterns, performance metrics,
 * user behavior analytics, and threat assessments.
 */
public class AnalyticsReport {
    
    private final double threatScore;
    private final Map<String, Object> performanceAnalysis;
    private final Map<String, Object> userBehaviorAnalysis;
    private final Map<String, Object> tenantAnalysis;
    private final Map<String, Object> trendAnalysis;
    private final Instant generatedAt;
    
    public AnalyticsReport() {
        this.threatScore = 0.0;
        this.performanceAnalysis = Map.of();
        this.userBehaviorAnalysis = Map.of();
        this.tenantAnalysis = Map.of();
        this.trendAnalysis = Map.of();
        this.generatedAt = Instant.now();
    }
    
    public AnalyticsReport(
            double threatScore,
            Map<String, Object> performanceAnalysis,
            Map<String, Object> userBehaviorAnalysis,
            Map<String, Object> tenantAnalysis,
            Map<String, Object> trendAnalysis,
            Instant generatedAt
    ) {
        this.threatScore = threatScore;
        this.performanceAnalysis = performanceAnalysis;
        this.userBehaviorAnalysis = userBehaviorAnalysis;
        this.tenantAnalysis = tenantAnalysis;
        this.trendAnalysis = trendAnalysis;
        this.generatedAt = generatedAt;
    }
    
    // Getters
    public double getThreatScore() { return threatScore; }
    public Map<String, Object> getPerformanceAnalysis() { return performanceAnalysis; }
    public Map<String, Object> getUserBehaviorAnalysis() { return userBehaviorAnalysis; }
    public Map<String, Object> getTenantAnalysis() { return tenantAnalysis; }
    public Map<String, Object> getTrendAnalysis() { return trendAnalysis; }
    public Instant getGeneratedAt() { return generatedAt; }
    
    /**
     * Get threat level based on threat score
     */
    public String getThreatLevel() {
        if (threatScore >= 0.8) return "HIGH";
        if (threatScore >= 0.5) return "MEDIUM";
        if (threatScore >= 0.2) return "LOW";
        return "MINIMAL";
    }
    
    /**
     * Check if immediate action is required based on threat score
     */
    public boolean requiresImmediateAction() {
        return threatScore >= 0.7;
    }
    
    /**
     * Get performance status
     */
    public String getPerformanceStatus() {
        Object trend = performanceAnalysis.get("performance_trend");
        if (trend != null && "degraded".equals(trend.toString())) {
            return "DEGRADED";
        }
        return "NORMAL";
    }
    
    /**
     * Get summary of key findings
     */
    public String getSummary() {
        StringBuilder summary = new StringBuilder();
        
        summary.append("Threat Level: ").append(getThreatLevel())
               .append(" (Score: ").append(String.format("%.2f", threatScore)).append("), ");
        
        summary.append("Performance: ").append(getPerformanceStatus()).append(", ");
        
        summary.append("Users Analyzed: ").append(userBehaviorAnalysis.size()).append(", ");
        
        summary.append("Tenants Analyzed: ").append(tenantAnalysis.size());
        
        if (requiresImmediateAction()) {
            summary.append(" - IMMEDIATE ACTION REQUIRED");
        }
        
        return summary.toString();
    }
    
    /**
     * Check if there are performance issues
     */
    public boolean hasPerformanceIssues() {
        return "DEGRADED".equals(getPerformanceStatus());
    }
    
    /**
     * Get number of users with suspicious behavior
     */
    public long getSuspiciousUserCount() {
        return userBehaviorAnalysis.entrySet().stream()
            .mapToLong(entry -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> userStats = (Map<String, Object>) entry.getValue();
                Object successRate = userStats.get("success_rate");
                if (successRate instanceof Number) {
                    return ((Number) successRate).doubleValue() < 0.5 ? 1 : 0;
                }
                return 0;
            })
            .sum();
    }
    
    /**
     * Get average success rate across all users
     */
    public double getAverageSuccessRate() {
        return userBehaviorAnalysis.values().stream()
            .mapToDouble(userStats -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> stats = (Map<String, Object>) userStats;
                Object successRate = stats.get("success_rate");
                if (successRate instanceof Number) {
                    return ((Number) successRate).doubleValue();
                }
                return 0.0;
            })
            .average()
            .orElse(0.0);
    }
    
    @Override
    public String toString() {
        return "AnalyticsReport{" +
                "threatScore=" + threatScore +
                ", threatLevel='" + getThreatLevel() + '\'' +
                ", performanceStatus='" + getPerformanceStatus() + '\'' +
                ", usersAnalyzed=" + userBehaviorAnalysis.size() +
                ", tenantsAnalyzed=" + tenantAnalysis.size() +
                ", suspiciousUsers=" + getSuspiciousUserCount() +
                ", averageSuccessRate=" + String.format("%.2f", getAverageSuccessRate()) +
                ", generatedAt=" + generatedAt +
                '}';
    }
}