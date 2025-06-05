#!/bin/bash

# Build Real OpenSearch Cedarling Security Plugin
echo "Building OpenSearch Cedarling Security Plugin..."

# Create plugin directory structure
mkdir -p plugin/{META-INF,org/opensearch/security/cedarling}

# Create plugin descriptor
cat > plugin/plugin-descriptor.properties << 'EOF'
name=opensearch-security-cedarling
description=OpenSearch Security Plugin with Cedarling Integration for Data-Based Authorization
version=2.11.0.0
opensearch.version=2.11.0
java.version=11
classname=org.opensearch.security.cedarling.CedarlingSecurityPlugin
has.native.controller=false
EOF

# Copy Java source files to plugin
cp -r src/main/java/org/opensearch/security/cedarling/* plugin/org/opensearch/security/cedarling/

# Create a simple JAR structure
cd plugin
jar cf ../opensearch-security-cedarling-2.11.0.0.jar .
cd ..

echo "Plugin JAR created: opensearch-security-cedarling-2.11.0.0.jar"

# Extract OpenSearch if needed
if [ ! -d "opensearch-2.11.0" ]; then
    echo "Extracting OpenSearch..."
    tar -xzf opensearch-2.11.0-linux-x64.tar.gz
fi

# Install plugin
echo "Installing Cedarling Security Plugin..."
cd opensearch-2.11.0
bin/opensearch-plugin install file://$(pwd)/../opensearch-security-cedarling-2.11.0.0.jar --batch

# Configure OpenSearch
cat >> config/opensearch.yml << 'EOF'

# Cedarling Security Plugin Configuration
cedarling.enabled: true
cedarling.policy_store_id: "opensearch-security-store"
cedarling.timeout_ms: 5000
cedarling.audit.enabled: true

# Network settings
network.host: 0.0.0.0
http.port: 5000
discovery.type: single-node

# Disable security for demo
plugins.security.disabled: true
EOF

echo "OpenSearch configured with Cedarling Security Plugin"
echo "Starting OpenSearch..."

# Start OpenSearch
export OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g"
bin/opensearch