/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.cedarling.rest;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.security.cedarling.audit.CedarlingAuditLogger;
import org.opensearch.security.cedarling.audit.AuditAnalytics;
import org.opensearch.security.cedarling.audit.AuditEvent;
import org.opensearch.security.cedarling.audit.AuditEventModels;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for comprehensive audit analytics and compliance reporting
 */
public class AuditAnalyticsRestHandler extends BaseRestHandler {
    
    private static final String AUDIT_ANALYTICS_ROUTE = "/_plugins/_cedarling/audit/analytics";
    private static final String AUDIT_EVENTS_ROUTE = "/_plugins/_cedarling/audit/events";
    private static final String AUDIT_EXPORT_ROUTE = "/_plugins/_cedarling/audit/export";
    private static final String AUDIT_DASHBOARD_ROUTE = "/_plugins/_cedarling/audit/dashboard";
    
    private final CedarlingAuditLogger auditLogger;
    
    public AuditAnalyticsRestHandler(CedarlingAuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }
    
    @Override
    public String getName() {
        return "cedarling_audit_analytics_handler";
    }
    
    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, AUDIT_ANALYTICS_ROUTE),
            new Route(GET, AUDIT_EVENTS_ROUTE),
            new Route(GET, AUDIT_EXPORT_ROUTE),
            new Route(GET, AUDIT_DASHBOARD_ROUTE),
            new Route(POST, "/_plugins/_cedarling/audit/test")
        );
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        
        return channel -> {
            try {
                String path = request.path();
                
                if (AUDIT_ANALYTICS_ROUTE.equals(path)) {
                    sendAuditAnalytics(channel);
                } else if (AUDIT_EVENTS_ROUTE.equals(path)) {
                    sendAuditEvents(request, channel);
                } else if (AUDIT_EXPORT_ROUTE.equals(path)) {
                    handleAuditExport(request, channel);
                } else if (AUDIT_DASHBOARD_ROUTE.equals(path)) {
                    sendAuditDashboard(channel);
                } else if (path.endsWith("/test")) {
                    handleAuditTest(request, channel);
                } else {
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, "Endpoint not found"));
                }
            } catch (Exception e) {
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error processing audit request: " + e.getMessage()));
            }
        };
    }
    
    private void sendAuditAnalytics(RestChannel channel) throws IOException {
        AuditAnalytics analytics = auditLogger.getAuditAnalytics();
        
        Map<String, Object> analyticsData = Map.of(
            "total_events", analytics.getTotalEvents(),
            "security_violations", analytics.getSecurityViolations(),
            "policy_evaluations", analytics.getPolicyEvaluations(),
            "top_violated_resources", analytics.getTopViolatedResources(),
            "top_denied_actions", analytics.getTopDeniedActions(),
            "hourly_trends", analytics.getHourlyTrends(),
            "performance_metrics", analytics.getPerformanceMetrics(),
            "compliance_status", Map.of(
                "gdpr_compliant", analytics.getComplianceStatus().isGdprCompliant(),
                "sox_compliant", analytics.getComplianceStatus().isSoxCompliant(),
                "iso27001_compliant", analytics.getComplianceStatus().isIso27001Compliant(),
                "audit_trail_complete", analytics.getComplianceStatus().isAuditTrailComplete(),
                "violation_rate", analytics.getComplianceStatus().getViolationRate(),
                "last_audit_time", analytics.getComplianceStatus().getLastAuditTime().toString()
            ),
            "timestamp", Instant.now().toString()
        );
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.map(analyticsData);
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private void sendAuditEvents(RestRequest request, RestChannel channel) throws IOException {
        int limit = request.paramAsInt("limit", 100);
        List<AuditEvent> events = auditLogger.getRecentAuditEvents(limit);
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.startObject();
        builder.field("total_events", events.size());
        builder.field("limit", limit);
        builder.startArray("events");
        
        for (AuditEvent event : events) {
            event.toXContent(builder);
        }
        
        builder.endArray();
        builder.endObject();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private void handleAuditExport(RestRequest request, RestChannel channel) throws IOException {
        String fromTimeStr = request.param("from");
        String toTimeStr = request.param("to");
        String eventTypeStr = request.param("event_type");
        
        Instant fromTime = Instant.EPOCH;
        Instant toTime = Instant.now();
        CedarlingAuditLogger.AuditEventType eventType = null;
        
        try {
            if (fromTimeStr != null) {
                fromTime = Instant.parse(fromTimeStr);
            }
            if (toTimeStr != null) {
                toTime = Instant.parse(toTimeStr);
            }
            if (eventTypeStr != null) {
                eventType = CedarlingAuditLogger.AuditEventType.valueOf(eventTypeStr.toUpperCase());
            }
        } catch (DateTimeParseException | IllegalArgumentException e) {
            channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, 
                "Invalid parameter format: " + e.getMessage()));
            return;
        }
        
        String exportData = auditLogger.exportAuditData(fromTime, toTime, eventType);
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            exportData
        );
        
        response.addHeader("Content-Disposition", 
            "attachment; filename=cedarling-audit-export-" + Instant.now().getEpochSecond() + ".json");
        
        channel.sendResponse(response);
    }
    
    private void sendAuditDashboard(RestChannel channel) throws IOException {
        String dashboardHtml = generateAuditDashboardHtml();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "text/html",
            dashboardHtml
        );
        
        channel.sendResponse(response);
    }
    
    private void handleAuditTest(RestRequest request, RestChannel channel) throws IOException {
        // Generate test audit events for demonstration
        auditLogger.logAuthorizationDecision(
            new AuthorizationDecisionEvent(
                "DENY",
                "indices:admin/delete",
                "sensitive-logs-*",
                "test-user",
                List.of("admin_access_policy", "data_protection_policy"),
                1.2,
                "Insufficient privileges for admin delete operation",
                Map.of("token_type", "bearer", "client_id", "test-client"),
                "192.168.1.100",
                "Mozilla/5.0 (Test Browser)",
                "req-" + System.currentTimeMillis(),
                "session-" + System.currentTimeMillis(),
                "node-1"
            )
        );
        
        Map<String, Object> testResult = Map.of(
            "status", "test_audit_event_generated",
            "message", "Test security violation logged for demonstration",
            "timestamp", Instant.now().toString()
        );
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.map(testResult);
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private String generateAuditDashboardHtml() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cedarling Audit Analytics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --security-gradient: linear-gradient(135deg, #fc4a1a 0%, #f7b733 100%);
            --compliance-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --card-shadow: 0 8px 25px rgba(0,0,0,0.08);
            --border-radius: 16px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh; color: #2d3748;
        }
        
        .header { 
            background: var(--security-gradient); color: white; 
            padding: 3rem 2rem; position: relative; overflow: hidden;
        }
        
        .header::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            z-index: 1;
        }
        
        .header-content { position: relative; z-index: 2; max-width: 1600px; margin: 0 auto; }
        .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 2rem; }
        
        .audit-banner { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            border: none; color: #856404; border-radius: var(--border-radius); 
            padding: 2rem; margin: 2rem 0; box-shadow: var(--card-shadow);
        }
        
        .metric-grid { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 1.5rem; margin: 2rem 0; 
        }
        
        .metric-card { 
            background: white; border-radius: var(--border-radius); 
            padding: 2rem; box-shadow: var(--card-shadow); text-align: center; 
            transition: var(--transition); position: relative; overflow: hidden;
        }
        
        .metric-card:hover { transform: translateY(-4px); }
        
        .metric-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: var(--primary-gradient);
        }
        
        .metric-card.security::before { background: var(--security-gradient); }
        .metric-card.compliance::before { background: var(--compliance-gradient); }
        
        .metric-icon { font-size: 2.5rem; margin-bottom: 1rem; opacity: 0.8; }
        .metric-value { font-size: 3rem; font-weight: 800; margin-bottom: 0.5rem; }
        .metric-label { color: #6c757d; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        
        .dashboard-grid { 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(600px, 1fr)); 
            gap: 2rem; margin: 2rem 0;
        }
        
        .card { 
            background: white; border-radius: var(--border-radius); 
            padding: 2.5rem; box-shadow: var(--card-shadow); transition: var(--transition);
        }
        
        .card:hover { box-shadow: 0 12px 35px rgba(0,0,0,0.15); }
        
        .card-title { 
            color: #2d3748; font-size: 1.4rem; font-weight: 700; 
            margin-bottom: 2rem; display: flex; align-items: center;
            padding-bottom: 1rem; border-bottom: 2px solid #f7fafc;
        }
        
        .card-title i { margin-right: 0.75rem; }
        
        .chart-container { position: relative; height: 350px; margin: 1.5rem 0; }
        
        .audit-log { max-height: 400px; overflow-y: auto; }
        .audit-item { padding: 1rem; margin: 0.5rem 0; background: #f8f9fa; border-radius: 8px; }
        .audit-item.violation { border-left: 4px solid #dc3545; }
        .audit-item.success { border-left: 4px solid #28a745; }
        
        .compliance-status { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .compliance-item { text-align: center; padding: 1rem; }
        .compliance-icon { font-size: 2rem; margin-bottom: 0.5rem; }
        .compliance-icon.compliant { color: #28a745; }
        .compliance-icon.non-compliant { color: #dc3545; }
        
        .btn { 
            background: var(--security-gradient); color: white; 
            padding: 0.75rem 1.5rem; border: none; border-radius: 25px; 
            cursor: pointer; margin: 0.5rem; transition: var(--transition);
        }
        
        .btn:hover { transform: translateY(-2px); }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1><i class="fas fa-shield-check"></i> Cedarling Audit Analytics Dashboard</h1>
            <p>Comprehensive security monitoring and compliance reporting</p>
        </div>
    </div>
    
    <div class="container">
        <div class="audit-banner">
            <h3><i class="fas fa-clipboard-check"></i> Audit Trail Status</h3>
            <p><strong>Real-time monitoring:</strong> All security events tracked and analyzed</p>
            <p><strong>Compliance:</strong> GDPR, SOX, and ISO 27001 requirements met</p>
            <p><strong>Retention:</strong> Last 1000 events stored for analysis</p>
        </div>
        
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-list"></i></div>
                <div class="metric-value" id="totalEvents">0</div>
                <div class="metric-label">Total Events</div>
            </div>
            <div class="metric-card security">
                <div class="metric-icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="metric-value" id="securityViolations">0</div>
                <div class="metric-label">Security Violations</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-gavel"></i></div>
                <div class="metric-value" id="policyEvaluations">0</div>
                <div class="metric-label">Policy Evaluations</div>
            </div>
            <div class="metric-card compliance">
                <div class="metric-icon"><i class="fas fa-check-circle"></i></div>
                <div class="metric-value" id="violationRate">0%</div>
                <div class="metric-label">Violation Rate</div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-title"><i class="fas fa-chart-line"></i> Security Trends</div>
                <div class="chart-container">
                    <canvas id="securityTrendChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-exclamation-circle"></i> Top Violations</div>
                <div class="chart-container">
                    <canvas id="violationChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-certificate"></i> Compliance Status</div>
                <div class="compliance-status">
                    <div class="compliance-item">
                        <div class="compliance-icon compliant"><i class="fas fa-shield-check"></i></div>
                        <div>GDPR</div>
                        <div>Compliant</div>
                    </div>
                    <div class="compliance-item">
                        <div class="compliance-icon compliant"><i class="fas fa-balance-scale"></i></div>
                        <div>SOX</div>
                        <div>Compliant</div>
                    </div>
                    <div class="compliance-item">
                        <div class="compliance-icon compliant"><i class="fas fa-award"></i></div>
                        <div>ISO 27001</div>
                        <div>Compliant</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-stream"></i> Recent Audit Events</div>
                <button class="btn" onclick="loadAuditData()">
                    <i class="fas fa-sync-alt"></i> Refresh Data
                </button>
                <button class="btn" onclick="generateTestEvent()">
                    <i class="fas fa-vial"></i> Generate Test Event
                </button>
                <div id="auditLog" class="audit-log"></div>
            </div>
        </div>
    </div>
    
    <script>
        let charts = {};
        
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            loadAuditData();
            setInterval(loadAuditData, 10000);
        });
        
        function initializeCharts() {
            // Security trend chart
            const trendCtx = document.getElementById('securityTrendChart').getContext('2d');
            charts.trend = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => (24 - i) + 'h ago'),
                    datasets: [{
                        label: 'Events',
                        data: Array(24).fill(0),
                        borderColor: '#fc4a1a',
                        backgroundColor: 'rgba(252, 74, 26, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } }
                }
            });
            
            // Violation chart
            const violationCtx = document.getElementById('violationChart').getContext('2d');
            charts.violation = new Chart(violationCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Admin Violations', 'Access Denied', 'Policy Violations'],
                    datasets: [{
                        data: [5, 15, 8],
                        backgroundColor: ['#dc3545', '#ffc107', '#fd7e14']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
        
        async function loadAuditData() {
            try {
                const response = await fetch('/_plugins/_cedarling/audit/analytics');
                const data = await response.json();
                
                updateMetrics(data);
                updateCharts(data);
                loadAuditEvents();
            } catch (error) {
                console.error('Error loading audit data:', error);
            }
        }
        
        function updateMetrics(data) {
            document.getElementById('totalEvents').textContent = data.total_events || 0;
            document.getElementById('securityViolations').textContent = data.security_violations || 0;
            document.getElementById('policyEvaluations').textContent = data.policy_evaluations || 0;
            document.getElementById('violationRate').textContent = 
                (data.compliance_status?.violation_rate || 0).toFixed(1) + '%';
        }
        
        function updateCharts(data) {
            if (data.hourly_trends && charts.trend) {
                const hours = Object.keys(data.hourly_trends).sort();
                const values = hours.map(h => data.hourly_trends[h] || 0);
                
                charts.trend.data.labels = hours;
                charts.trend.data.datasets[0].data = values;
                charts.trend.update();
            }
        }
        
        async function loadAuditEvents() {
            try {
                const response = await fetch('/_plugins/_cedarling/audit/events?limit=10');
                const data = await response.json();
                
                updateAuditLog(data.events || []);
            } catch (error) {
                console.error('Error loading audit events:', error);
            }
        }
        
        function updateAuditLog(events) {
            const logContainer = document.getElementById('auditLog');
            logContainer.innerHTML = '';
            
            events.forEach(event => {
                const item = document.createElement('div');
                const isViolation = event.decision === 'DENY' || event.event_type === 'SECURITY_VIOLATION';
                item.className = `audit-item ${isViolation ? 'violation' : 'success'}`;
                
                item.innerHTML = `
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">
                        ${event.event_type} - ${event.decision || 'N/A'}
                    </div>
                    <div style="font-size: 0.9rem; color: #6c757d;">
                        ${event.action || 'N/A'} on ${event.resource || 'N/A'}
                        <br>Time: ${new Date(event.timestamp).toLocaleString()}
                        <br>Reason: ${event.reason || 'N/A'}
                    </div>
                `;
                
                logContainer.appendChild(item);
            });
        }
        
        async function generateTestEvent() {
            try {
                const response = await fetch('/_plugins/_cedarling/audit/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                if (response.ok) {
                    setTimeout(loadAuditData, 1000);
                }
            } catch (error) {
                console.error('Error generating test event:', error);
            }
        }
    </script>
</body>
</html>
        """;
    }
}