package org.opensearch.security.cedarling.sync;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.cedarling.CedarlingSecurityPlugin;
import org.opensearch.security.cedarling.model.PolicyStoreSnapshot;
import org.opensearch.security.cedarling.service.CedarlingService;
import org.opensearch.security.cedarling.sync.PolicyStoreSynchronizer.SynchronizationStatus;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for PolicyStoreSynchronizer
 */
public class PolicyStoreSynchronizerTest {
    
    private ThreadPool threadPool;
    private Settings settings;
    
    @Mock
    private CedarlingService cedarlingService;
    
    @Mock
    private CloseableHttpClient httpClient;
    
    @Mock
    private CloseableHttpResponse httpResponse;
    
    @Mock
    private StatusLine statusLine;
    
    @Mock
    private HttpEntity httpEntity;
    
    private PolicyStoreSynchronizer synchronizer;
    
    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        
        threadPool = new TestThreadPool("test");
        settings = Settings.builder()
            .put(CedarlingSecurityPlugin.CEDARLING_ENDPOINT.getKey(), "http://localhost:8080")
            .put(CedarlingSecurityPlugin.CEDARLING_POLICY_STORE_ID.getKey(), "test-store")
            .put(CedarlingSecurityPlugin.CEDARLING_ENABLED.getKey(), true)
            .put("cedarling.sync.interval_seconds", 10L)
            .build();
        
        synchronizer = new PolicyStoreSynchronizer(settings, threadPool, cedarlingService, httpClient);
    }
    
    @Test
    public void testSynchronizerInitialization() {
        assertNotNull(synchronizer);
        
        SynchronizationStatus status = synchronizer.getStatus();
        assertTrue(status.isEnabled());
        assertEquals(10L, status.getSyncIntervalSeconds());
        assertNull(status.getCurrentVersion());
        assertEquals(0, status.getPolicyCount());
        assertFalse(status.isHealthy()); // No initial sync yet
    }
    
    @Test
    public void testSuccessfulPolicyStoreSync() throws IOException {
        // Mock metadata response
        String metadataJson = """
            {
                "version": "v1.2.3",
                "last_modified": "2024-01-15T10:30:00Z",
                "policy_count": 5,
                "checksum": "abc123"
            }
            """;
        
        // Mock snapshot response
        String snapshotJson = """
            {
                "version": "v1.2.3",
                "last_modified": "2024-01-15T10:30:00Z",
                "policies": [
                    {
                        "id": "policy1",
                        "content": "permit(principal, action, resource);",
                        "description": "Test policy",
                        "effect": "permit"
                    }
                ],
                "schema": {
                    "entities": {},
                    "actions": {},
                    "common_types": {}
                },
                "metadata": {}
            }
            """;
        
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(httpEntity);
        
        // First call returns metadata, second returns snapshot
        when(httpEntity.getContent())
            .thenReturn(new ByteArrayInputStream(metadataJson.getBytes(StandardCharsets.UTF_8)))
            .thenReturn(new ByteArrayInputStream(snapshotJson.getBytes(StandardCharsets.UTF_8)));
        
        // Test force sync
        CompletableFuture<Boolean> syncResult = synchronizer.forceSyncCheck();
        Boolean updated = syncResult.join();
        
        assertTrue(updated);
        
        SynchronizationStatus status = synchronizer.getStatus();
        assertEquals("v1.2.3", status.getCurrentVersion());
        assertEquals(1, status.getPolicyCount());
        assertTrue(status.isHealthy());
        
        // Verify cache invalidation was called
        verify(cedarlingService).invalidateAuthorizationCache();
    }
    
    @Test
    public void testNoUpdateNeeded() throws IOException {
        // First sync
        String metadataJson = """
            {
                "version": "v1.0.0",
                "last_modified": "2024-01-15T10:00:00Z",
                "policy_count": 3,
                "checksum": "def456"
            }
            """;
        
        String snapshotJson = """
            {
                "version": "v1.0.0",
                "last_modified": "2024-01-15T10:00:00Z",
                "policies": [],
                "schema": {"entities": {}, "actions": {}, "common_types": {}},
                "metadata": {}
            }
            """;
        
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(httpEntity);
        when(httpEntity.getContent())
            .thenReturn(new ByteArrayInputStream(metadataJson.getBytes(StandardCharsets.UTF_8)))
            .thenReturn(new ByteArrayInputStream(snapshotJson.getBytes(StandardCharsets.UTF_8)))
            .thenReturn(new ByteArrayInputStream(metadataJson.getBytes(StandardCharsets.UTF_8))); // Same version
        
        // First sync
        CompletableFuture<Boolean> firstSync = synchronizer.forceSyncCheck();
        assertTrue(firstSync.join());
        
        // Second sync with same version
        CompletableFuture<Boolean> secondSync = synchronizer.forceSyncCheck();
        assertFalse(secondSync.join()); // No update needed
    }
    
    @Test
    public void testSyncFailureHandling() throws IOException {
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(500); // Server error
        
        CompletableFuture<Boolean> syncResult = synchronizer.forceSyncCheck();
        Boolean updated = syncResult.join();
        
        assertFalse(updated);
        
        SynchronizationStatus status = synchronizer.getStatus();
        assertNull(status.getCurrentVersion());
        assertEquals(0, status.getPolicyCount());
        assertFalse(status.isHealthy());
    }
    
    @Test
    public void testNetworkException() throws IOException {
        when(httpClient.execute(any())).thenThrow(new IOException("Network error"));
        
        CompletableFuture<Boolean> syncResult = synchronizer.forceSyncCheck();
        Boolean updated = syncResult.join();
        
        assertFalse(updated);
        assertFalse(synchronizer.isHealthy());
    }
    
    @Test
    public void testSynchronizerLifecycle() {
        // Test start
        synchronizer.start();
        
        SynchronizationStatus status = synchronizer.getStatus();
        assertTrue(status.isEnabled());
        
        // Test stop
        synchronizer.stop();
        
        // Verify no more scheduled tasks
        // Note: In a real test, you'd verify the scheduled task was cancelled
    }
    
    @Test
    public void testDisabledSynchronizer() {
        Settings disabledSettings = Settings.builder()
            .put(CedarlingSecurityPlugin.CEDARLING_ENABLED.getKey(), false)
            .build();
        
        PolicyStoreSynchronizer disabledSync = new PolicyStoreSynchronizer(
            disabledSettings, threadPool, cedarlingService, httpClient
        );
        
        disabledSync.start(); // Should not start actual sync
        
        SynchronizationStatus status = disabledSync.getStatus();
        assertFalse(status.isEnabled());
    }
    
    @Test
    public void testCurrentSnapshotAccess() {
        assertNull(synchronizer.getCurrentSnapshot());
        
        // After a successful sync, snapshot should be available
        // This would be tested in integration tests with actual sync
    }
    
    @Test
    public void testHealthStatus() {
        // Initially not healthy (no sync yet)
        assertFalse(synchronizer.isHealthy());
        
        // After successful sync with current timestamp, should be healthy
        // This requires more complex mocking of internal state
    }
    
    public void tearDown() {
        if (threadPool != null) {
            ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
        }
    }
}