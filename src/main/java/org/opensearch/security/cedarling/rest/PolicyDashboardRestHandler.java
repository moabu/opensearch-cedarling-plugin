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
import org.opensearch.security.cedarling.service.EmbeddedCedarlingService;
import org.opensearch.security.cedarling.service.PolicyDecisionTracker;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.time.Instant;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for the interactive policy decision visualization dashboard
 * Provides real-time monitoring and analytics for Cedarling policy decisions
 */
public class PolicyDashboardRestHandler extends BaseRestHandler {
    
    private static final String DASHBOARD_ROUTE = "/_plugins/_cedarling/dashboard";
    private static final String DASHBOARD_DATA_ROUTE = "/_plugins/_cedarling/dashboard/data";
    private static final String POLICY_METRICS_ROUTE = "/_plugins/_cedarling/dashboard/metrics";
    
    private final EmbeddedCedarlingService cedarlingService;
    private final PolicyDecisionTracker decisionTracker;
    
    public PolicyDashboardRestHandler(EmbeddedCedarlingService cedarlingService, PolicyDecisionTracker decisionTracker) {
        this.cedarlingService = cedarlingService;
        this.decisionTracker = decisionTracker;
    }
    
    @Override
    public String getName() {
        return "cedarling_policy_dashboard_handler";
    }
    
    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, DASHBOARD_ROUTE),
            new Route(GET, DASHBOARD_DATA_ROUTE),
            new Route(GET, POLICY_METRICS_ROUTE),
            new Route(POST, "/_plugins/_cedarling/dashboard/simulate")
        );
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        
        return channel -> {
            try {
                String path = request.path();
                
                if (DASHBOARD_ROUTE.equals(path)) {
                    sendDashboardInterface(channel);
                } else if (DASHBOARD_DATA_ROUTE.equals(path)) {
                    sendDashboardData(channel);
                } else if (POLICY_METRICS_ROUTE.equals(path)) {
                    sendPolicyMetrics(channel);
                } else if (path.endsWith("/simulate")) {
                    handleSimulateDecision(request, channel);
                } else {
                    channel.sendResponse(new BytesRestResponse(RestStatus.NOT_FOUND, "Endpoint not found"));
                }
            } catch (Exception e) {
                channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, 
                    "Error processing dashboard request: " + e.getMessage()));
            }
        };
    }
    
    private void sendDashboardInterface(RestChannel channel) throws IOException {
        String dashboardHtml = generateDashboardHtml();
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "text/html",
            dashboardHtml
        );
        
        channel.sendResponse(response);
    }
    
    private void sendDashboardData(RestChannel channel) throws IOException {
        Map<String, Object> dashboardData = decisionTracker.getDashboardData();
        
        // Add plugin-specific information
        dashboardData.put("plugin_info", Map.of(
            "name", "opensearch-security-cedarling",
            "version", "2.11.0.0",
            "engine", "uniffi.cedarling_uniffi.Cedarling",
            "cluster_integrated", true,
            "real_time_monitoring", true
        ));
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.map(dashboardData);
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private void sendPolicyMetrics(RestChannel channel) throws IOException {
        Map<String, Object> metrics = Map.of(
            "total_decisions", decisionTracker.getTotalDecisions(),
            "allow_rate", decisionTracker.getAllowRate(),
            "avg_response_time_ms", cedarlingService.getAverageResponseTime(),
            "active_policies", cedarlingService.getActivePolicyCount(),
            "policy_statistics", decisionTracker.getPolicyStatistics(),
            "user_statistics", decisionTracker.getUserStatistics(),
            "resource_statistics", decisionTracker.getResourceStatistics(),
            "timestamp", Instant.now().toString()
        );
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.map(metrics);
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json", 
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private void handleSimulateDecision(RestRequest request, RestChannel channel) throws IOException {
        // Parse request body for simulation parameters
        Map<String, Object> simulationRequest = request.contentParser().map();
        
        String action = (String) simulationRequest.getOrDefault("action", "indices:data/read/search");
        String resource = (String) simulationRequest.getOrDefault("resource", "logs-test");
        String user = (String) simulationRequest.getOrDefault("user", "dashboard-user");
        
        // Perform actual authorization using embedded Cedarling service
        boolean isAuthorized = cedarlingService.authorize(action, resource, user);
        
        Map<String, Object> simulationResult = Map.of(
            "decision", isAuthorized ? "ALLOW" : "DENY",
            "action", action,
            "resource", resource,
            "user", user,
            "policies_evaluated", cedarlingService.getEvaluatedPolicies(),
            "response_time_ms", cedarlingService.getLastResponseTime(),
            "reason", "Live plugin simulation using embedded Cedarling engine",
            "timestamp", Instant.now().toString(),
            "plugin_integrated", true
        );
        
        // Record decision in tracker
        decisionTracker.recordDecision(simulationResult);
        
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.map(Map.of("status", "success", "simulation", simulationResult));
        
        BytesRestResponse response = new BytesRestResponse(
            RestStatus.OK,
            "application/json",
            BytesReference.bytes(builder)
        );
        
        channel.sendResponse(response);
    }
    
    private String generateDashboardHtml() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenSearch Cedarling Policy Dashboard - Live Plugin Integration</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --danger-gradient: linear-gradient(135deg, #fc4a1a 0%, #f7b733 100%);
            --info-gradient: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --card-shadow: 0 8px 25px rgba(0,0,0,0.08);
            --hover-shadow: 0 12px 35px rgba(0,0,0,0.15);
            --border-radius: 16px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            color: #2d3748;
        }
        
        .header { 
            background: var(--primary-gradient);
            color: white; 
            padding: 3rem 2rem; 
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            z-index: 1;
        }
        
        .header-content {
            position: relative; z-index: 2;
            max-width: 1600px; margin: 0 auto;
        }
        
        .header h1 {
            font-size: 2.5rem; font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .live-integration-banner { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border: none; color: #155724; 
            border-radius: var(--border-radius); 
            padding: 2rem; margin: 2rem auto;
            box-shadow: var(--card-shadow);
            max-width: 1600px;
            position: relative; overflow: hidden;
        }
        
        .live-integration-banner::before {
            content: ''; position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
            background: var(--success-gradient);
        }
        
        .container { max-width: 1600px; margin: 0 auto; padding: 2rem; }
        
        .metric-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); 
            gap: 1.5rem; margin: 2rem 0; 
        }
        
        .metric-card { 
            background: white; border-radius: var(--border-radius); 
            padding: 2rem; box-shadow: var(--card-shadow);
            text-align: center; position: relative; overflow: hidden;
            transition: var(--transition);
        }
        
        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--hover-shadow);
        }
        
        .metric-card::before {
            content: ''; position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: var(--primary-gradient);
        }
        
        .metric-card.success::before { background: var(--success-gradient); }
        .metric-card.danger::before { background: var(--danger-gradient); }
        .metric-card.info::before { background: var(--info-gradient); }
        
        .metric-icon { font-size: 2rem; margin-bottom: 1rem; opacity: 0.8; }
        
        .metric-value { 
            font-size: 3rem; font-weight: 800; 
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text; margin-bottom: 0.5rem;
        }
        
        .metric-label { 
            color: #6c757d; font-weight: 600; font-size: 0.95rem;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        
        .dashboard-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(600px, 1fr)); 
            gap: 2rem; margin: 2rem 0;
        }
        
        .card { 
            background: white; border-radius: var(--border-radius); 
            padding: 2.5rem; box-shadow: var(--card-shadow);
            transition: var(--transition);
        }
        
        .card:hover { box-shadow: var(--hover-shadow); }
        
        .card-title { 
            color: #2d3748; font-size: 1.4rem; font-weight: 700; 
            margin-bottom: 2rem; display: flex; align-items: center;
            padding-bottom: 1rem; border-bottom: 2px solid #f7fafc;
        }
        
        .card-title i {
            margin-right: 0.75rem;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .chart-container { 
            position: relative; height: 350px; margin: 1.5rem 0;
            background: #fafbfc; border-radius: 12px; padding: 1rem;
        }
        
        .live-indicator { 
            display: inline-block; width: 10px; height: 10px; 
            background: #48bb78; border-radius: 50%; 
            animation: pulse 2s infinite; margin-right: 0.75rem;
            box-shadow: 0 0 8px rgba(72, 187, 120, 0.6);
        }
        
        @keyframes pulse { 
            0% { opacity: 1; transform: scale(1); } 
            50% { opacity: 0.7; transform: scale(1.1); } 
            100% { opacity: 1; transform: scale(1); } 
        }
        
        .btn { 
            background: var(--primary-gradient); color: white; 
            padding: 0.75rem 1.5rem; border: none; border-radius: 25px; 
            cursor: pointer; font-size: 0.9rem; font-weight: 600;
            transition: var(--transition); display: inline-flex; align-items: center;
            text-transform: uppercase; letter-spacing: 0.5px;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
            margin: 0.5rem;
        }
        
        .btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }
        
        .btn i { margin-right: 0.5rem; }
        
        .btn-success { 
            background: var(--success-gradient);
            box-shadow: 0 4px 12px rgba(17, 153, 142, 0.3);
        }
        
        .btn-success:hover { 
            box-shadow: 0 6px 20px rgba(17, 153, 142, 0.4);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1><i class="fas fa-shield-alt"></i> OpenSearch Cedarling Policy Dashboard</h1>
            <p><span class="live-indicator"></span>Live plugin integration with embedded Cedarling engine</p>
        </div>
    </div>
    
    <div class="live-integration-banner">
        <h3><i class="fas fa-plug"></i> Live Plugin Integration Active</h3>
        <p><strong>Plugin:</strong> opensearch-security-cedarling v2.11.0.0 (LOADED IN OPENSEARCH)</p>
        <p><strong>Engine:</strong> uniffi.cedarling_uniffi.Cedarling (Embedded in plugin)</p>
        <p><strong>Integration:</strong> Real OpenSearch cluster with authentic plugin deployment</p>
        <p><strong>Monitoring:</strong> Live policy decisions from actual Cedarling engine</p>
    </div>
    
    <div class="container">
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-clipboard-list"></i></div>
                <div class="metric-value" id="totalDecisions">0</div>
                <div class="metric-label">Total Decisions</div>
            </div>
            <div class="metric-card success">
                <div class="metric-icon"><i class="fas fa-percentage"></i></div>
                <div class="metric-value" id="allowRate">0%</div>
                <div class="metric-label">Allow Rate</div>
            </div>
            <div class="metric-card info">
                <div class="metric-icon"><i class="fas fa-tachometer-alt"></i></div>
                <div class="metric-value" id="avgResponseTime">0ms</div>
                <div class="metric-label">Avg Response Time</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-shield-alt"></i></div>
                <div class="metric-value" id="activePolicies">0</div>
                <div class="metric-label">Active Policies</div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-title"><i class="fas fa-chart-line"></i> Policy Decision Trends</div>
                <div class="chart-container">
                    <canvas id="trendChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-shield-alt"></i> Policy Performance</div>
                <div class="chart-container">
                    <canvas id="policyChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-cogs"></i> Live Plugin Controls</div>
                <div style="padding: 2rem;">
                    <p><strong>Plugin Status:</strong> <span style="color: #28a745;">ACTIVE</span></p>
                    <p><strong>Integration:</strong> <span style="color: #28a745;">LIVE OPENSEARCH</span></p>
                    <p><strong>Engine:</strong> uniffi.cedarling_uniffi.Cedarling</p>
                    <br>
                    <button class="btn btn-success" onclick="loadDashboardData()">
                        <i class="fas fa-sync-alt"></i> Refresh Live Data
                    </button>
                    <button class="btn" onclick="simulateDecision()">
                        <i class="fas fa-play"></i> Test Plugin Decision
                    </button>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title"><i class="fas fa-database"></i> Resource Access</div>
                <div class="chart-container">
                    <canvas id="resourceChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let charts = {};
        
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            loadDashboardData();
            setInterval(loadDashboardData, 5000); // Refresh every 5 seconds
        });
        
        function initializeCharts() {
            if (typeof Chart === 'undefined') {
                console.error('Chart.js not loaded, retrying...');
                setTimeout(initializeCharts, 1000);
                return;
            }
            
            // Trend Chart
            const trendCtx = document.getElementById('trendChart').getContext('2d');
            charts.trend = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: ['5m ago', '4m ago', '3m ago', '2m ago', '1m ago', 'Now'],
                    datasets: [{
                        label: 'Allow',
                        data: [0, 0, 0, 0, 0, 0],
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
                        tension: 0.4, fill: true
                    }, {
                        label: 'Deny',
                        data: [0, 0, 0, 0, 0, 0],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.4, fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'top' } },
                    scales: { y: { beginAtZero: true } }
                }
            });
            
            // Policy Chart
            const policyCtx = document.getElementById('policyChart').getContext('2d');
            charts.policy = new Chart(policyCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Loading...'],
                    datasets: [{
                        data: [1],
                        backgroundColor: ['#667eea']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                }
            });
            
            // Resource Chart
            const resourceCtx = document.getElementById('resourceChart').getContext('2d');
            charts.resource = new Chart(resourceCtx, {
                type: 'bar',
                data: {
                    labels: ['Loading...'],
                    datasets: [{
                        label: 'Access Attempts',
                        data: [0],
                        backgroundColor: '#667eea'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } }
                }
            });
            
            console.log('Charts initialized for live plugin dashboard');
        }
        
        async function loadDashboardData() {
            try {
                const response = await fetch('/_plugins/_cedarling/dashboard/data');
                const data = await response.json();
                
                updateMetrics(data);
                updateCharts(data);
                
                console.log('Live plugin data loaded:', data);
            } catch (error) {
                console.error('Error loading live plugin data:', error);
            }
        }
        
        function updateMetrics(data) {
            if (data.total_decisions !== undefined) {
                document.getElementById('totalDecisions').textContent = data.total_decisions;
            }
            if (data.allow_rate !== undefined) {
                document.getElementById('allowRate').textContent = data.allow_rate + '%';
            }
            if (data.avg_response_time_ms !== undefined) {
                document.getElementById('avgResponseTime').textContent = data.avg_response_time_ms + 'ms';
            }
            if (data.active_policies !== undefined) {
                document.getElementById('activePolicies').textContent = data.active_policies;
            }
        }
        
        function updateCharts(data) {
            if (data.policy_statistics && charts.policy) {
                const policies = Object.keys(data.policy_statistics);
                const policyData = policies.map(name => 
                    (data.policy_statistics[name].allow || 0) + (data.policy_statistics[name].deny || 0)
                );
                
                charts.policy.data.labels = policies;
                charts.policy.data.datasets[0].data = policyData;
                charts.policy.data.datasets[0].backgroundColor = [
                    '#667eea', '#28a745', '#ffc107', '#dc3545', '#6f42c1'
                ];
                charts.policy.update();
            }
            
            if (data.resource_statistics && charts.resource) {
                const resources = Object.keys(data.resource_statistics);
                const accessData = resources.map(name => data.resource_statistics[name].access_attempts || 0);
                
                charts.resource.data.labels = resources;
                charts.resource.data.datasets[0].data = accessData;
                charts.resource.update();
            }
        }
        
        async function simulateDecision() {
            try {
                const response = await fetch('/_plugins/_cedarling/dashboard/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'indices:data/read/search',
                        resource: 'logs-dashboard-test',
                        user: 'plugin-test-user'
                    })
                });
                
                const result = await response.json();
                console.log('Live plugin simulation result:', result);
                
                // Refresh data after simulation
                setTimeout(loadDashboardData, 500);
            } catch (error) {
                console.error('Error simulating decision:', error);
            }
        }
    </script>
</body>
</html>
        """;
    }
}