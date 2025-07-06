#!/bin/bash

# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
NAMESPACE="elastic-system"
OPERATOR_NAME="elastic-operator"
DEPLOY_METHOD="helm"
MANAGED_NAMESPACES=""
STACK_VERSION="9.0.0"
DEPLOY_SAMPLES="false"
DEPLOY_FULL_STACK="false"
DEPLOY_MONITORING="false"
DEPLOY_INGRESS="false"
DEPLOY_CERT_MANAGER="false"
USE_ELASTIC_CLOUD="false"
DEPLOY_COMPREHENSIVE="false"
CLOUD_PROVIDER=""
ELASTIC_CLOUD_URL="${ELASTIC_CLOUD_URL:-}"
ELASTIC_CLOUD_API_KEY="${ELASTIC_CLOUD_API_KEY:-}"
WAIT="true"
TIMEOUT="300s"

# Auto-load Elastic Cloud credentials if using --elastic-cloud and credentials aren't set
auto_load_elastic_credentials() {
    if [[ "$USE_ELASTIC_CLOUD" == "true" && (-z "$ELASTIC_CLOUD_URL" || -z "$ELASTIC_CLOUD_API_KEY") ]]; then
        if [[ -f "./setup-elastic-cloud.sh" ]]; then
            log_info "Loading Elastic Cloud credentials from setup-elastic-cloud.sh..."
            source ./setup-elastic-cloud.sh > /dev/null
        fi
    fi
}

# Help function
show_help() {
    cat << EOF
Elastic Cloud on Kubernetes (ECK) Deployment Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -m, --method <METHOD>       Deployment method: helm, manifests, dev (default: helm)
    -n, --namespace <NAMESPACE> Operator namespace (default: elastic-system)
    --name <NAME>              Operator name (default: elastic-operator)
    --managed-ns <NAMESPACES>  Comma-separated managed namespaces (default: all)
    --stack-version <VERSION>  Elastic Stack version (default: 9.0.0)
    --samples                  Deploy sample Elasticsearch and Kibana
    --full-stack               Deploy complete ELK stack with all components
    --monitoring               Deploy monitoring and beats
    --ingress                  Deploy Nginx ingress controller for external access
    --cert-manager             Deploy cert-manager for TLS certificate automation
    --elastic-cloud            Use Elastic Cloud instead of self-hosted (requires ELASTIC_CLOUD_URL and ELASTIC_CLOUD_API_KEY env vars)
    --comprehensive            Deploy absolutely everything with all components (Fleet, Logstash, Enterprise Search, Maps, all Beats, APM)
    --cloud-provider <PROVIDER> Cloud provider specific configurations (aws, gcp, azure)
    --all                      Deploy everything (operator, stack, monitoring, ingress, cert-manager)
    --no-wait                  Don't wait for deployment to be ready
    --timeout <TIMEOUT>        Timeout for waiting (default: 300s)
    -h, --help                 Show this help message

DEPLOYMENT METHODS:
    helm        Deploy using Helm charts (default)
    manifests   Deploy using generated Kubernetes manifests
    dev         Deploy in development mode (builds and pushes image)

EXAMPLES:
    # Deploy using Helm (default)
    $0

    # Deploy using manifests with custom namespace
    $0 --method manifests --namespace my-elastic-system

    # Deploy in development mode with samples
    $0 --method dev --samples

    # Deploy complete ELK stack with monitoring
    $0 --full-stack --monitoring

    # Deploy everything with external access
    $0 --all

    # Deploy monitoring to Elastic Cloud (edit setup-elastic-cloud.sh first)
    $0 --elastic-cloud --monitoring
    
    # Deploy ABSOLUTELY EVERYTHING to Elastic Cloud (Fleet, Logstash, Enterprise Search, Maps, all Beats, APM)
    $0 --elastic-cloud --comprehensive
    
    # Deploy comprehensive self-hosted stack with all components
    $0 --comprehensive
    
    # Or set environment variables manually
    export ELASTIC_CLOUD_URL="https://xxx.es.io:443"
    export ELASTIC_CLOUD_API_KEY="your-api-key"
    $0 --elastic-cloud --comprehensive

    # Deploy with AWS ALB ingress
    $0 --comprehensive --cloud-provider aws --ingress

    # Deploy with GCP Load Balancer
    $0 --comprehensive --cloud-provider gcp --ingress

    # Deploy with restricted namespaces
    $0 --managed-ns "namespace1,namespace2"

PREREQUISITES:
    - kubectl configured with target cluster
    - For helm method: helm 3.x installed
    - For dev method: Docker and registry access configured
    - Sufficient RBAC permissions in target cluster
EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is required but not found"
        exit 1
    fi
    
    # Check cluster access
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot access Kubernetes cluster. Check your kubeconfig"
        exit 1
    fi
    
    # Check helm for helm deployment
    if [[ "$DEPLOY_METHOD" == "helm" ]] && ! command -v helm &> /dev/null; then
        log_error "helm is required for helm deployment method"
        exit 1
    fi
    
    # Check make and docker for dev deployment
    if [[ "$DEPLOY_METHOD" == "dev" ]]; then
        if ! command -v make &> /dev/null; then
            log_error "make is required for dev deployment method"
            exit 1
        fi
        if ! command -v docker &> /dev/null; then
            log_error "docker is required for dev deployment method"
            exit 1
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Deploy using Helm
deploy_helm() {
    log_info "Deploying ECK operator using Helm..."
    
    # Create namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Check if operator is already deployed
    if helm list -n "$NAMESPACE" | grep -q "$OPERATOR_NAME"; then
        log_info "ECK operator already deployed, skipping"
        return
    fi
    
    # Prepare helm command - use stable release version instead of SNAPSHOT
    local helm_cmd="helm install $OPERATOR_NAME ./deploy/eck-operator -n $NAMESPACE --set=image.tag=3.0.0"
    
    # Add managed namespaces if specified
    if [[ -n "$MANAGED_NAMESPACES" ]]; then
        helm_cmd="$helm_cmd --set=installCRDs=false --set=createClusterScopedResources=false"
        helm_cmd="$helm_cmd --set=managedNamespaces='{$MANAGED_NAMESPACES}'"
        helm_cmd="$helm_cmd --set=webhook.enabled=false"
        
        # Install CRDs separately for restricted deployment
        log_info "Installing CRDs for restricted deployment..."
        helm install elastic-operator-crds ./deploy/eck-operator/charts/eck-operator-crds
    fi
    
    # Execute helm install
    eval "$helm_cmd"
    
    if [[ "$WAIT" == "true" ]]; then
        log_info "Waiting for operator to be ready..."
        kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod/"$OPERATOR_NAME-0" -n "$NAMESPACE"
    fi
    
    log_success "ECK operator deployed successfully using Helm"
}

# Deploy using manifests
deploy_manifests() {
    log_info "Deploying ECK operator using Kubernetes manifests..."
    
    # Check if manifest generation tools are available
    if [[ ! -f "./hack/manifest-gen/manifest-gen.sh" ]]; then
        log_error "Manifest generation script not found. Run from project root directory."
        exit 1
    fi
    
    # Create namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Install CRDs
    log_info "Installing CRDs..."
    if [[ -f "config/crds/v1/all-crds.yaml" ]]; then
        kubectl apply -f config/crds/v1/all-crds.yaml
    else
        log_warning "CRDs file not found, generating..."
        make generate-manifests
        kubectl apply -f config/crds/v1/all-crds.yaml
    fi
    
    # Generate and apply operator manifest
    log_info "Generating operator manifest..."
    local manifest_cmd="./hack/manifest-gen/manifest-gen.sh -g --namespace=$NAMESPACE"
    manifest_cmd="$manifest_cmd --set=nameOverride=$OPERATOR_NAME --set=fullnameOverride=$OPERATOR_NAME"
    
    if [[ -n "$MANAGED_NAMESPACES" ]]; then
        manifest_cmd="$manifest_cmd --profile=restricted --set=installCRDs=true"
        manifest_cmd="$manifest_cmd --set=managedNamespaces=\"{$MANAGED_NAMESPACES}\""
    fi
    
    eval "$manifest_cmd" | kubectl apply -f -
    
    if [[ "$WAIT" == "true" ]]; then
        log_info "Waiting for operator to be ready..."
        kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod/"$OPERATOR_NAME-0" -n "$NAMESPACE"
    fi
    
    log_success "ECK operator deployed successfully using manifests"
}

# Deploy in development mode
deploy_dev() {
    log_info "Deploying ECK operator in development mode..."
    
    # Check if we're in the project root
    if [[ ! -f "Makefile" ]]; then
        log_error "Makefile not found. Run from project root directory."
        exit 1
    fi
    
    # Use make to deploy
    log_info "Building and deploying operator..."
    OPERATOR_NAMESPACE="$NAMESPACE" OPERATOR_NAME="$OPERATOR_NAME" make deploy
    
    if [[ "$WAIT" == "true" ]]; then
        log_info "Waiting for operator to be ready..."
        kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod/"$OPERATOR_NAME-0" -n "$NAMESPACE"
    fi
    
    log_success "ECK operator deployed successfully in development mode"
}

# Deploy samples
deploy_samples() {
    if [[ "$DEPLOY_SAMPLES" == "true" ]]; then
        log_info "Deploying sample Elasticsearch and Kibana..."
        
        # Check if samples exist
        if [[ -f "config/samples/kibana/kibana_es.yaml" ]]; then
            kubectl apply -f config/samples/kibana/kibana_es.yaml
            
            if [[ "$WAIT" == "true" ]]; then
                log_info "Waiting for Elasticsearch to be ready..."
                kubectl wait --for=condition=ready --timeout="$TIMEOUT" elasticsearch/elasticsearch-sample || true
                
                log_info "Waiting for Kibana to be ready..."
                kubectl wait --for=condition=ready --timeout="$TIMEOUT" kibana/kibana-sample || true
                
                log_info "Getting Elasticsearch credentials..."
                echo "Elasticsearch credentials:"
                echo "Username: elastic"
                echo -n "Password: "
                kubectl get secret elasticsearch-sample-es-elastic-user -o jsonpath='{.data.elastic}' | base64 -d
                echo ""
            fi
            
            log_success "Sample Elasticsearch and Kibana deployed"
        else
            log_warning "Sample files not found"
        fi
    fi
}

# Create Elastic Cloud credentials secret
create_elastic_cloud_secret() {
    if [[ "$USE_ELASTIC_CLOUD" == "true" ]]; then
        log_info "Creating Elastic Cloud credentials secret..."
        
        # Validate credentials from environment variables
        if [[ -z "$ELASTIC_CLOUD_URL" || -z "$ELASTIC_CLOUD_API_KEY" ]]; then
            log_error "Elastic Cloud URL and API key are required when using --elastic-cloud"
            log_error "Set environment variables:"
            log_error "  export ELASTIC_CLOUD_URL=\"https://xxx.es.io:443\""
            log_error "  export ELASTIC_CLOUD_API_KEY=\"your-api-key\""
            exit 1
        fi
        
        # Create namespace if it doesn't exist
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
        
        # Decode API key if it appears to be base64 encoded
        local api_key="$ELASTIC_CLOUD_API_KEY"
        if [[ "$api_key" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] && [[ ${#api_key} -gt 20 ]]; then
            # Try to decode if it looks like base64
            local decoded_key
            decoded_key=$(echo "$api_key" | base64 -d 2>/dev/null || echo "$api_key")
            if [[ "$decoded_key" =~ ^[^:]+:[^:]+$ ]]; then
                log_info "Detected base64-encoded API key, using decoded value"
                api_key="$decoded_key"
            fi
        fi
        
        # Create secret for Elastic Cloud credentials
        kubectl create secret generic elastic-cloud-credentials \
            --from-literal=url="$ELASTIC_CLOUD_URL" \
            --from-literal=api-key="$api_key" \
            -n "$NAMESPACE" \
            --dry-run=client -o yaml | kubectl apply -f -
        
        log_success "Elastic Cloud credentials secret created"
    fi
}

# Deploy comprehensive Elastic stack
deploy_full_stack() {
    if [[ "$DEPLOY_FULL_STACK" == "true" ]]; then
        if [[ "$USE_ELASTIC_CLOUD" == "true" ]]; then
            log_info "Setting up comprehensive monitoring for Elastic Cloud..."
            create_elastic_cloud_secret
            
            # Deploy all observability components that send to Elastic Cloud
            deploy_comprehensive_elastic_cloud_stack
            
            log_success "Comprehensive Elastic Cloud monitoring deployed"
            log_info "Elastic Cloud URL: $ELASTIC_CLOUD_URL"
        else
            log_info "Deploying comprehensive self-hosted Elastic Stack..."
            
            # Deploy complete self-hosted stack
            deploy_comprehensive_self_hosted_stack
            
            log_success "Comprehensive self-hosted Elastic Stack deployed"
        fi
    fi
}

# Deploy everything for Elastic Cloud monitoring
deploy_comprehensive_elastic_cloud_stack() {
    log_info "Deploying complete Elastic Stack observability to Elastic Cloud..."
    
    # Create namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy ALL the observability components from the samples
    log_info "Deploying comprehensive observability components..."
    
    # Deploy ALL the major Elastic components for cloud monitoring
    
    # 1. APM Server
    deploy_apm_server_cloud
    
    # 2. Fleet Server (for agent management)
    deploy_fleet_server_cloud
    
    # 3. Logstash (for data processing)
    deploy_logstash_cloud
    
    # 4. All Beats (Metricbeat, Filebeat, Auditbeat, Heartbeat, Packetbeat)
    deploy_all_beats_for_cloud
    
    # 5. Elastic Agents with all integrations
    deploy_elastic_agents_for_cloud
    
    # 6. Deploy additional samples and recipes
    deploy_additional_cloud_samples
    
    log_success "All observability components deployed to send data to Elastic Cloud"
}

# Deploy APM Server for Elastic Cloud
deploy_apm_server_cloud() {
    log_info "Deploying APM Server for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: apm.k8s.elastic.co/v1
kind: ApmServer
metadata:
  name: apm-server-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 1
  config:
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    apm-server:
      rum:
        enabled: true
        allow_origins: ["*"]
      capture_personal_data: false
  podTemplate:
    spec:
      containers:
      - name: apm-server
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
EOF
}

# Deploy Fleet Server for Elastic Cloud
deploy_fleet_server_cloud() {
    log_info "Deploying Fleet Server for agent management..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: agent.k8s.elastic.co/v1alpha1
kind: Agent
metadata:
  name: fleet-server-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  mode: fleet
  fleetServerEnabled: true
  deployment:
    replicas: 1
    podTemplate:
      spec:
        containers:
        - name: agent
          env:
          - name: FLEET_SERVER_ENABLE
            value: "1"
          - name: FLEET_SERVER_ELASTICSEARCH_HOST
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: FLEET_SERVER_ELASTICSEARCH_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
          - name: FLEET_SERVER_POLICY
            value: "fleet-server-policy"
          - name: FLEET_URL
            value: "https://fleet-server-cloud-agent-http:8220"
          resources:
            limits:
              memory: 1Gi
              cpu: 200m
            requests:
              memory: 512Mi
              cpu: 100m
EOF
}

# Deploy Logstash for Elastic Cloud
deploy_logstash_cloud() {
    log_info "Deploying Logstash for data processing..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: logstash.k8s.elastic.co/v1alpha1
kind: Logstash
metadata:
  name: logstash-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 1
  config:
    pipeline.workers: 1
    config.reload.automatic: true
  pipelines:
  - pipeline.id: main
    config.string: |
      input {
        beats {
          port => 5044
        }
        http {
          port => 8080
        }
      }
      filter {
        if [kubernetes] {
          mutate {
            add_field => { "[@metadata][index]" => "logstash-kubernetes-%{+YYYY.MM.dd}" }
          }
        } else {
          mutate {
            add_field => { "[@metadata][index]" => "logstash-generic-%{+YYYY.MM.dd}" }
          }
        }
      }
      output {
        elasticsearch {
          hosts => ["\${ELASTIC_CLOUD_URL}"]
          api_key => "\${ELASTIC_CLOUD_API_KEY}"
          index => "%{[@metadata][index]}"
        }
      }
  podTemplate:
    spec:
      containers:
      - name: logstash
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
        resources:
          limits:
            memory: 2Gi
            cpu: 1
          requests:
            memory: 1Gi
            cpu: 500m
  services:
  - name: beats
    service:
      spec:
        type: ClusterIP
        ports:
        - port: 5044
          name: beats
          protocol: TCP
          targetPort: 5044
  - name: http
    service:
      spec:
        type: ClusterIP
        ports:
        - port: 8080
          name: http
          protocol: TCP
          targetPort: 8080
EOF
}

# Deploy additional cloud samples and specialized components
deploy_additional_cloud_samples() {
    log_info "Deploying additional specialized components..."
    
    # Deploy Synthetic Monitoring Agent
    if [[ -f "config/recipes/elastic-agent/synthetic-monitoring.yaml" ]]; then
        # Modify to point to Elastic Cloud and apply
        sed "s|elasticsearch:|elasticsearch:\n      hosts: [\"$ELASTIC_CLOUD_URL\"]\n      api_key: \"\${ELASTIC_CLOUD_API_KEY}\"|g" \
            config/recipes/elastic-agent/synthetic-monitoring.yaml | kubectl apply -f - || true
        log_info "Deployed Synthetic Monitoring"
    fi
    
    # Deploy multi-output agent configuration
    if [[ -f "config/recipes/elastic-agent/multi-output.yaml" ]]; then
        # Modify to point to Elastic Cloud and apply
        sed "s|elasticsearch:|elasticsearch:\n      hosts: [\"$ELASTIC_CLOUD_URL\"]\n      api_key: \"\${ELASTIC_CLOUD_API_KEY}\"|g" \
            config/recipes/elastic-agent/multi-output.yaml | kubectl apply -f - || true
        log_info "Deployed Multi-output Agent"
    fi
    
    # Deploy KSM sharding for large clusters
    if [[ -f "config/recipes/elastic-agent/ksm-sharding.yaml" ]]; then
        sed "s|elasticsearch:|elasticsearch:\n      hosts: [\"$ELASTIC_CLOUD_URL\"]\n      api_key: \"\${ELASTIC_CLOUD_API_KEY}\"|g" \
            config/recipes/elastic-agent/ksm-sharding.yaml | kubectl apply -f - || true
        log_info "Deployed KSM Sharding for large cluster monitoring"
    fi
}

# Deploy all types of beats for Elastic Cloud
deploy_all_beats_for_cloud() {
    log_info "Deploying all Beat types for comprehensive monitoring..."
    
    # We already have Metricbeat and Filebeat from the previous function
    # Let's add the other beat types
    
    # Deploy Auditbeat for security monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: auditbeat-cloud
  namespace: $NAMESPACE
spec:
  type: auditbeat
  version: $STACK_VERSION
  config:
    auditbeat.modules:
    - module: auditd
      audit_rule_files: [ '\${path.config}/audit.rules.d/*.conf' ]
      audit_rules: |
        -w /etc/passwd -p wa -k identity
        -w /etc/group -p wa -k identity
        -w /etc/shadow -p wa -k identity
        -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
    - module: file_integrity
      paths:
      - /bin
      - /usr/bin
      - /sbin
      - /usr/sbin
      - /etc
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        containers:
        - name: auditbeat
          securityContext:
            runAsUser: 0
            capabilities:
              add:
              - AUDIT_CONTROL
              - AUDIT_READ
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
EOF

    # Deploy Heartbeat for uptime monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: heartbeat-cloud
  namespace: $NAMESPACE
spec:
  type: heartbeat
  version: $STACK_VERSION
  config:
    heartbeat.monitors:
    - type: http
      id: elastic-cloud-http
      name: "Elastic Cloud HTTP"
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      schedule: '@every 30s'
    - type: icmp
      id: kubernetes-api-icmp
      name: "Kubernetes API ICMP"
      hosts: ["kubernetes.default.svc.cluster.local"]
      schedule: '@every 30s'
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
  deployment:
    podTemplate:
      spec:
        containers:
        - name: heartbeat
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
EOF

    # Deploy Packetbeat for network monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: packetbeat-cloud
  namespace: $NAMESPACE
spec:
  type: packetbeat
  version: $STACK_VERSION
  config:
    packetbeat.interfaces.device: any
    packetbeat.flows:
      timeout: 30s
      period: 10s
    packetbeat.protocols:
      dns:
        ports: [53]
        include_authorities: true
        include_additionals: true
      http:
        ports: [80, 8080, 8000, 5000, 8002]
        real_ip_header: "X-Forwarded-For"
      tls:
        ports: [443, 993, 995, 5223, 8443, 8883, 9243]
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
    - add_docker_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        containers:
        - name: packetbeat
          securityContext:
            runAsUser: 0
            capabilities:
              add:
              - NET_ADMIN
              - NET_RAW
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
        hostNetwork: true
        dnsPolicy: ClusterFirstWithHostNet
EOF

    log_info "Deployed Auditbeat, Heartbeat, and Packetbeat for comprehensive monitoring"
}

# Deploy Elastic Agents with multiple integrations for cloud
deploy_elastic_agents_for_cloud() {
    log_info "Deploying Elastic Agents with comprehensive integrations..."
    
    # Deploy Elastic Agent with system integration
    cat <<EOF | kubectl apply -f -
apiVersion: agent.k8s.elastic.co/v1alpha1
kind: Agent
metadata:
  name: elastic-agent-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  config:
    outputs:
      default:
        type: elasticsearch
        hosts: ["\${ELASTIC_CLOUD_URL}"]
        api_key: "\${ELASTIC_CLOUD_API_KEY}"
    inputs:
    - id: system-integration
      type: system/metrics
      data_stream:
        namespace: default
      use_output: default
      streams:
      - id: system/metrics-system.cpu
        data_stream:
          dataset: system.cpu
        metricsets: ["cpu"]
        cpu.metrics: ["percentages", "normalized_percentages"]
      - id: system/metrics-system.memory  
        data_stream:
          dataset: system.memory
        metricsets: ["memory"]
      - id: system/metrics-system.network
        data_stream:
          dataset: system.network
        metricsets: ["network"]
      - id: system/metrics-system.filesystem
        data_stream:
          dataset: system.filesystem
        metricsets: ["filesystem"]
    - id: kubernetes-integration
      type: kubernetes/metrics
      data_stream:
        namespace: default
      use_output: default
      streams:
      - id: kubernetes/metrics-kubernetes.container
        data_stream:
          dataset: kubernetes.container
        metricsets: ["container"]
      - id: kubernetes/metrics-kubernetes.node
        data_stream:
          dataset: kubernetes.node
        metricsets: ["node"]
      - id: kubernetes/metrics-kubernetes.pod
        data_stream:
          dataset: kubernetes.pod
        metricsets: ["pod"]
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        containers:
        - name: agent
          securityContext:
            runAsUser: 0
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          volumeMounts:
          - name: proc
            mountPath: /hostfs/proc
            readOnly: true
          - name: cgroup
            mountPath: /hostfs/sys/fs/cgroup
            readOnly: true
          - name: varlibdockercontainers
            mountPath: /var/lib/docker/containers
            readOnly: true
        volumes:
        - name: proc
          hostPath:
            path: /proc
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: elastic-agent-cloud
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: elastic-agent-cloud
rules:
- apiGroups: [""]
  resources: ["nodes", "namespaces", "events", "pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["extensions"]
  resources: ["replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["statefulsets", "deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: elastic-agent-cloud
subjects:
- kind: ServiceAccount
  name: elastic-agent-cloud
  namespace: $NAMESPACE
roleRef:
  kind: ClusterRole
  name: elastic-agent-cloud
  apiGroup: rbac.authorization.k8s.io
EOF

    log_info "Deployed Elastic Agent with system and Kubernetes integrations"
}

# Deploy complete self-hosted stack
deploy_comprehensive_self_hosted_stack() {
    log_info "Deploying complete self-hosted Elastic Stack with all components..."
    
    # Deploy using the comprehensive Helm chart with ALL components enabled
    local helm_cmd="helm install eck-stack ./deploy/eck-stack -n $NAMESPACE"
    helm_cmd="$helm_cmd --set eck-elasticsearch.enabled=true,eck-elasticsearch.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-kibana.enabled=true,eck-kibana.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-logstash.enabled=true,eck-logstash.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-apm-server.enabled=true,eck-apm-server.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-enterprise-search.enabled=true,eck-enterprise-search.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-beats.enabled=true,eck-beats.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-agent.enabled=true,eck-agent.version=$STACK_VERSION"
    helm_cmd="$helm_cmd --set eck-fleet-server.enabled=true,eck-fleet-server.version=$STACK_VERSION"
    
    # Fix Enterprise Search reference
    helm_cmd="$helm_cmd --set eck-enterprise-search.elasticsearchRef.name=elasticsearch"
    helm_cmd="$helm_cmd --set eck-apm-server.elasticsearchRef.name=elasticsearch"
    helm_cmd="$helm_cmd --set eck-logstash.elasticsearchRef.name=elasticsearch"
    helm_cmd="$helm_cmd --set eck-beats.elasticsearchRef.name=elasticsearch"
    helm_cmd="$helm_cmd --set eck-agent.elasticsearchRef.name=elasticsearch"
    helm_cmd="$helm_cmd --set eck-fleet-server.elasticsearchRef.name=elasticsearch"
    
    eval "$helm_cmd"
    
    # Also deploy additional samples not covered by Helm
    deploy_additional_samples
    
    if [[ "$WAIT" == "true" ]]; then
        log_info "Waiting for core services to be ready..."
        kubectl wait --for=condition=ready --timeout="$TIMEOUT" elasticsearch/elasticsearch -n "$NAMESPACE" || true
        kubectl wait --for=condition=ready --timeout="$TIMEOUT" kibana/kibana -n "$NAMESPACE" || true
        
        log_info "Getting Elasticsearch credentials..."
        echo "Elasticsearch credentials:"
        echo "Username: elastic"
        echo -n "Password: "
        kubectl get secret elasticsearch-es-elastic-user -n "$NAMESPACE" -o jsonpath='{.data.elastic}' | base64 -d 2>/dev/null || echo "Not ready yet"
        echo ""
        
        log_info "Access URLs:"
        echo "Elasticsearch: kubectl port-forward -n $NAMESPACE svc/elasticsearch-es-http 9200"
        echo "Kibana: kubectl port-forward -n $NAMESPACE svc/kibana-kb-http 5601"
        echo "Enterprise Search: kubectl port-forward -n $NAMESPACE svc/enterprise-search-ent-http 3002"
        echo "APM Server: kubectl port-forward -n $NAMESPACE svc/apm-server-apm-http 8200"
    fi
}

# Deploy additional samples not covered by Helm charts
deploy_additional_samples() {
    log_info "Deploying additional Elastic Stack components from samples..."
    
    # Deploy Elastic Maps Server
    if [[ -f "config/recipes/maps/01-ems.yaml" ]]; then
        kubectl apply -f config/recipes/maps/01-ems.yaml || true
        log_info "Deployed Elastic Maps Server"
    fi
    
    # Deploy comprehensive monitoring
    if [[ -f "config/recipes/beats/stack_monitoring.yaml" ]]; then
        kubectl apply -f config/recipes/beats/stack_monitoring.yaml || true
        log_info "Deployed Stack Monitoring"
    fi
}

# Deploy monitoring and beats
deploy_monitoring() {
    if [[ "$DEPLOY_MONITORING" == "true" ]]; then
        if [[ "$USE_ELASTIC_CLOUD" == "true" ]]; then
            log_info "Deploying monitoring agents for Elastic Cloud..."
            deploy_elastic_cloud_monitoring
        else
            log_info "Deploying self-hosted monitoring stack..."
            
            # Deploy beats for monitoring
            if [[ -f "config/recipes/beats/metricbeat_hosts.yaml" ]]; then
                kubectl apply -f config/recipes/beats/metricbeat_hosts.yaml
                log_info "Deployed Metricbeat for host monitoring"
            fi
            
            if [[ -f "config/recipes/beats/filebeat_no_autodiscover.yaml" ]]; then
                kubectl apply -f config/recipes/beats/filebeat_no_autodiscover.yaml
                log_info "Deployed Filebeat for log collection"
            fi
            
            # Deploy stack monitoring if full stack is also enabled
            if [[ "$DEPLOY_FULL_STACK" == "true" && -f "config/recipes/beats/stack_monitoring.yaml" ]]; then
                kubectl apply -f config/recipes/beats/stack_monitoring.yaml
                log_info "Deployed Stack Monitoring"
            fi
        fi
        
        log_success "Monitoring stack deployed successfully"
    fi
}

# Deploy monitoring agents for Elastic Cloud
deploy_elastic_cloud_monitoring() {
    log_info "Creating monitoring agents for Elastic Cloud connection..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy Metricbeat for system and Kubernetes monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: metricbeat-cloud
  namespace: $NAMESPACE
spec:
  type: metricbeat
  version: $STACK_VERSION
  config:
    metricbeat:
      autodiscover:
        providers:
        - type: kubernetes
          scope: cluster
          hints.enabled: true
          templates:
          - condition:
              contains:
                kubernetes.labels.scrape: metricbeat
            config:
            - module: prometheus
              period: 10s
              metricsets: ["collector"]
              hosts: ["\${data.host}:\${data.ports.http}"]
              metrics_path: /metrics
      modules:
      - module: system
        metricsets:
        - cpu
        - load
        - memory
        - network
        - process
        - process_summary
        - filesystem
        period: 10s
        processes: [".*"]
        cpu.metrics: ["percentages", "normalized_percentages"]
        core.metrics: ["percentages"]
      - module: kubernetes
        metricsets:
        - node
        - system
        - pod
        - container
        - volume
        period: 10s
        host: "\${NODE_NAME}"
        hosts: ["https://\${NODE_NAME}:10250"]
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        ssl.verification_mode: "none"
        add_metadata: true
    cloud.id: "\${ELASTIC_CLOUD_ID}"
    cloud.auth: "\${ELASTIC_CLOUD_AUTH}"
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        serviceAccountName: metricbeat
        automountServiceAccountToken: true
        terminationGracePeriodSeconds: 30
        dnsPolicy: ClusterFirstWithHostNet
        hostNetwork: true
        containers:
        - name: metricbeat
          securityContext:
            runAsUser: 0
          volumeMounts:
          - name: proc
            mountPath: /hostfs/proc
            readOnly: true
          - name: cgroup
            mountPath: /hostfs/sys/fs/cgroup
            readOnly: true
          - name: varlibdockercontainers
            mountPath: /var/lib/docker/containers
            readOnly: true
          - name: varlog
            mountPath: /var/log
            readOnly: true
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
        volumes:
        - name: proc
          hostPath:
            path: /proc
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
        - name: varlog
          hostPath:
            path: /var/log
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metricbeat
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: metricbeat
rules:
- apiGroups: [""]
  resources:
  - nodes
  - namespaces
  - events
  - pods
  - services
  verbs: ["get", "list", "watch"]
- apiGroups: ["extensions"]
  resources:
  - replicasets
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources:
  - statefulsets
  - deployments
  - replicasets
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources:
  - nodes/stats
  verbs: ["get"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: metricbeat
subjects:
- kind: ServiceAccount
  name: metricbeat
  namespace: $NAMESPACE
roleRef:
  kind: ClusterRole
  name: metricbeat
  apiGroup: rbac.authorization.k8s.io
EOF

    # Deploy Filebeat for log collection
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: filebeat-cloud
  namespace: $NAMESPACE
spec:
  type: filebeat
  version: $STACK_VERSION
  config:
    filebeat:
      autodiscover:
        providers:
        - type: kubernetes
          node: \${NODE_NAME}
          hints.enabled: true
          hints.default_config:
            type: container
            paths:
            - /var/log/containers/*\${data.kubernetes.container.id}.log
      inputs:
      - type: kubernetes
        paths:
        - /var/log/containers/*.log
        processors:
        - add_kubernetes_metadata:
            host: \${NODE_NAME}
            matchers:
            - logs_path:
                logs_path: "/var/log/containers/"
    cloud.id: "\${ELASTIC_CLOUD_ID}"
    cloud.auth: "\${ELASTIC_CLOUD_AUTH}"
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
    - add_docker_metadata: {}
    - add_kubernetes_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        serviceAccountName: filebeat
        terminationGracePeriodSeconds: 30
        dnsPolicy: ClusterFirstWithHostNet
        hostNetwork: true
        containers:
        - name: filebeat
          securityContext:
            runAsUser: 0
          volumeMounts:
          - name: varlibdockercontainers
            mountPath: /var/lib/docker/containers
            readOnly: true
          - name: varlog
            mountPath: /var/log
            readOnly: true
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
        volumes:
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
        - name: varlog
          hostPath:
            path: /var/log
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: filebeat
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: filebeat
rules:
- apiGroups: [""]
  resources:
  - namespaces
  - pods
  - nodes
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: filebeat
subjects:
- kind: ServiceAccount
  name: filebeat
  namespace: $NAMESPACE
roleRef:
  kind: ClusterRole
  name: filebeat
  apiGroup: rbac.authorization.k8s.io
EOF

    log_success "Elastic Cloud monitoring agents deployed"
    log_info "Metricbeat and Filebeat will send data to: $ELASTIC_CLOUD_URL"
}

# Deploy cert-manager
deploy_cert_manager() {
    if [[ "$DEPLOY_CERT_MANAGER" == "true" ]]; then
        log_info "Deploying cert-manager..."
        
        # Check if cert-manager is already installed
        if kubectl get namespace cert-manager &> /dev/null; then
            log_info "cert-manager namespace already exists, skipping installation"
            return
        fi
        
        # Install cert-manager CRDs and operator
        kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
        
        if [[ "$WAIT" == "true" ]]; then
            log_info "Waiting for cert-manager to be ready..."
            kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod -l app=cert-manager -n cert-manager
            kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod -l app=cainjector -n cert-manager
            kubectl wait --for=condition=ready --timeout="$TIMEOUT" pod -l app=webhook -n cert-manager
        fi
        
        # Apply cluster issuer for self-signed certificates
        log_info "Creating self-signed cluster issuer..."
        cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF
        
        log_success "cert-manager deployed successfully"
    fi
}

# Deploy ingress controller
deploy_ingress() {
    if [[ "$DEPLOY_INGRESS" == "true" ]]; then
        log_info "Deploying Nginx ingress controller..."
        
        # Check if ingress-nginx namespace already exists
        if kubectl get namespace ingress-nginx &> /dev/null; then
            log_info "ingress-nginx namespace already exists, skipping installation"
            return
        fi
        
        # Deploy nginx ingress controller
        kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
        
        if [[ "$WAIT" == "true" ]]; then
            log_info "Waiting for ingress controller to be ready..."
            kubectl wait --namespace ingress-nginx \
                --for=condition=ready pod \
                --selector=app.kubernetes.io/component=controller \
                --timeout="$TIMEOUT"
        fi
        
        log_success "Nginx ingress controller deployed successfully"
    fi
}

# Create ingress for Elastic services
deploy_elastic_ingress() {
    if [[ "$DEPLOY_INGRESS" == "true" && "$DEPLOY_FULL_STACK" == "true" ]]; then
        log_info "Creating ingress for Elastic services..."
        
        # Wait a bit for services to be created
        sleep 30
        
        # Create ingress for Kibana
        cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana-ingress
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "false"
    cert-manager.io/cluster-issuer: "selfsigned-issuer"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - kibana.local
    secretName: kibana-tls
  rules:
  - host: kibana.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kibana-kb-http
            port:
              number: 5601
EOF

        # Create ingress for Elasticsearch
        cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elasticsearch-ingress
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "false"
    cert-manager.io/cluster-issuer: "selfsigned-issuer"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - elasticsearch.local
    secretName: elasticsearch-tls
  rules:
  - host: elasticsearch.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: elasticsearch-es-http
            port:
              number: 9200
EOF
        
        log_success "Elastic ingress created successfully"
        log_info "Add to /etc/hosts: kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}' elasticsearch.local kibana.local"
    fi
}

# Main deployment logic
deploy() {
    # Auto-load Elastic Cloud credentials if needed
    auto_load_elastic_credentials
    
    log_info "Starting ECK deployment..."
    log_info "Method: $DEPLOY_METHOD"
    log_info "Namespace: $NAMESPACE"
    log_info "Operator Name: $OPERATOR_NAME"
    
    if [[ -n "$MANAGED_NAMESPACES" ]]; then
        log_info "Managed Namespaces: $MANAGED_NAMESPACES"
    fi
    
    case "$DEPLOY_METHOD" in
        "helm")
            deploy_helm
            ;;
        "manifests")
            deploy_manifests
            ;;
        "dev")
            deploy_dev
            ;;
        *)
            log_error "Unknown deployment method: $DEPLOY_METHOD"
            exit 1
            ;;
    esac
    
    # Deploy external dependencies first
    deploy_cert_manager
    deploy_ingress
    
    # Check if we should deploy comprehensive stacks
    if [[ "$DEPLOY_COMPREHENSIVE" == "true" && "$USE_ELASTIC_CLOUD" == "true" ]]; then
        log_info "Deploying comprehensive Elastic Cloud stack with ALL components..."
        deploy_comprehensive_elastic_cloud_stack
    elif [[ "$DEPLOY_COMPREHENSIVE" == "true" && "$USE_ELASTIC_CLOUD" != "true" ]]; then
        log_info "Deploying comprehensive self-hosted stack with ALL components..."
        deploy_comprehensive_self_hosted_stack
        deploy_hot_warm_cold_architecture
        deploy_advanced_logstash
        deploy_stack_config_policies
        deploy_elasticsearch_autoscaler
        deploy_security_policies
    elif [[ "$USE_ELASTIC_CLOUD" == "true" && "$DEPLOY_FULL_STACK" == "true" ]]; then
        log_info "Deploying basic Elastic Cloud stack..."
        deploy_comprehensive_elastic_cloud_stack
    elif [[ "$USE_ELASTIC_CLOUD" == "true" && "$DEPLOY_MONITORING" == "true" ]]; then
        log_info "Deploying Elastic Cloud monitoring only..."
        deploy_elastic_cloud_monitoring
    else
        # Deploy ECK components (original logic)
        deploy_samples
        deploy_full_stack
        deploy_monitoring
    fi
    
    # Deploy ingress for Elastic services last
    deploy_elastic_ingress
    deploy_cloud_provider_ingress
    
    log_success "ECK deployment completed successfully!"
    log_info "To check the operator status:"
    log_info "  kubectl get pods -n $NAMESPACE"
    log_info "To view operator logs:"
    log_info "  kubectl logs -f -n $NAMESPACE statefulset/$OPERATOR_NAME"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--method)
            DEPLOY_METHOD="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --name)
            OPERATOR_NAME="$2"
            shift 2
            ;;
        --managed-ns)
            MANAGED_NAMESPACES="$2"
            shift 2
            ;;
        --stack-version)
            STACK_VERSION="$2"
            shift 2
            ;;
        --samples)
            DEPLOY_SAMPLES="true"
            shift
            ;;
        --full-stack)
            DEPLOY_FULL_STACK="true"
            shift
            ;;
        --monitoring)
            DEPLOY_MONITORING="true"
            shift
            ;;
        --ingress)
            DEPLOY_INGRESS="true"
            shift
            ;;
        --cert-manager)
            DEPLOY_CERT_MANAGER="true"
            shift
            ;;
        --elastic-cloud)
            USE_ELASTIC_CLOUD="true"
            shift
            ;;
        --comprehensive)
            DEPLOY_COMPREHENSIVE="true"
            DEPLOY_FULL_STACK="true"
            DEPLOY_MONITORING="true"
            shift
            ;;
        --cloud-provider)
            CLOUD_PROVIDER="$2"
            shift 2
            ;;
        --all)
            DEPLOY_FULL_STACK="true"
            DEPLOY_MONITORING="true"
            DEPLOY_INGRESS="true"
            DEPLOY_CERT_MANAGER="true"
            shift
            ;;
        --no-wait)
            WAIT="false"
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate deployment method
if [[ "$DEPLOY_METHOD" != "helm" && "$DEPLOY_METHOD" != "manifests" && "$DEPLOY_METHOD" != "dev" ]]; then
    log_error "Invalid deployment method: $DEPLOY_METHOD"
    log_error "Valid methods: helm, manifests, dev"
    exit 1
fi

# Create Elastic Cloud credentials secret
create_elastic_cloud_credentials() {
    log_info "Creating Elastic Cloud credentials secret..."
    
    if [[ -z "$ELASTIC_CLOUD_URL" || -z "$ELASTIC_CLOUD_API_KEY" ]]; then
        log_error "ELASTIC_CLOUD_URL and ELASTIC_CLOUD_API_KEY must be set"
        exit 1
    fi
    
    # Check if API key is base64 encoded and decode if necessary
    local decoded_key="$ELASTIC_CLOUD_API_KEY"
    if echo "$ELASTIC_CLOUD_API_KEY" | base64 -d &>/dev/null; then
        log_info "Detected base64 encoded API key, decoding..."
        decoded_key=$(echo "$ELASTIC_CLOUD_API_KEY" | base64 -d)
    fi
    
    # Create the secret
    kubectl create secret generic elastic-cloud-credentials \
        --namespace="$NAMESPACE" \
        --from-literal=url="$ELASTIC_CLOUD_URL" \
        --from-literal=api-key="$decoded_key" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_success "Elastic Cloud credentials secret created"
}

# Deploy comprehensive Elastic Cloud stack (all components)
deploy_comprehensive_elastic_cloud_stack() {
    log_info "Deploying comprehensive Elastic Cloud stack with all components..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Elastic Cloud credentials secret first
    create_elastic_cloud_credentials
    
    # Deploy Fleet Server for Elastic Agent management
    deploy_fleet_server_cloud
    
    # Deploy Logstash for data processing
    deploy_logstash_cloud
    
    # Deploy Enterprise Search
    deploy_enterprise_search_cloud
    
    # Deploy Maps Server
    deploy_maps_server_cloud
    
    # Deploy all Beats for comprehensive monitoring
    deploy_all_beats_for_cloud
    
    # Deploy APM Server for application monitoring
    deploy_apm_server_cloud
    
    # Deploy advanced configurations
    deploy_stack_config_policies
    deploy_elasticsearch_autoscaler
    deploy_security_policies
    
    log_success "Comprehensive Elastic Cloud stack deployed successfully"
}

# Deploy Fleet Server for Elastic Cloud
deploy_fleet_server_cloud() {
    log_info "Deploying Fleet Server for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: agent.k8s.elastic.co/v1alpha1
kind: Agent
metadata:
  name: fleet-server-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  kibanaRef:
    name: kibana-kb
  elasticsearchRefs:
  - name: elasticsearch-es
  mode: fleet
  fleetServerEnabled: true
  fleetServerRef:
    name: fleet-server-cloud
  policyID: fleet-server-policy
  config:
    id: fleet-server-cloud
    secret_store_path: /mnt/elastic-internal/fleet-secrets
    server:
      host: 0.0.0.0
      port: 8220
  deployment:
    replicas: 1
    podTemplate:
      spec:
        automountServiceAccountToken: true
        containers:
        - name: agent
          env:
          - name: FLEET_SERVER_ENABLE
            value: "true"
          - name: FLEET_SERVER_ELASTICSEARCH_HOST
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: FLEET_SERVER_ELASTICSEARCH_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
          - name: FLEET_SERVER_SERVICE_TOKEN
            valueFrom:
              secretKeyRef:
                name: fleet-server-service-account
                key: token
          ports:
          - containerPort: 8220
            name: fleet-server
            protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: fleet-server-cloud
  namespace: $NAMESPACE
spec:
  selector:
    agent.k8s.elastic.co/name: fleet-server-cloud
  ports:
  - name: fleet-server
    port: 8220
    targetPort: 8220
EOF
    
    log_success "Fleet Server deployed"
}

# Deploy Logstash for Elastic Cloud
deploy_logstash_cloud() {
    log_info "Deploying Logstash for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: logstash.k8s.elastic.co/v1alpha1
kind: Logstash
metadata:
  name: logstash-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 2
  elasticsearchRefs:
  - name: elasticsearch-cloud
    clusterName: elasticsearch
  config:
    pipeline.workers: 2
    log.level: info
    xpack.monitoring.enabled: true
    xpack.monitoring.elasticsearch.hosts:
    - "\${ELASTIC_CLOUD_URL}"
    xpack.monitoring.elasticsearch.api_key: "\${ELASTIC_CLOUD_API_KEY}"
  pipelines:
  - pipeline.id: main
    config.string: |
      input {
        beats {
          port => 5044
        }
        http {
          port => 8080
          codec => json
        }
      }
      filter {
        if [fields][logstash_format] == "docker" {
          json {
            source => "message"
          }
          date {
            match => [ "timestamp", "ISO8601" ]
          }
        }
        mutate {
          add_field => { "logstash_processed" => true }
          add_field => { "logstash_timestamp" => "%{@timestamp}" }
        }
      }
      output {
        elasticsearch {
          hosts => ["\${ELASTIC_CLOUD_URL}"]
          api_key => "\${ELASTIC_CLOUD_API_KEY}"
          index => "logstash-processed-%{+YYYY.MM.dd}"
        }
      }
  podTemplate:
    spec:
      containers:
      - name: logstash
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
        ports:
        - containerPort: 5044
          name: beats
        - containerPort: 8080
          name: http
        resources:
          requests:
            memory: 2Gi
            cpu: 1000m
          limits:
            memory: 4Gi
            cpu: 2000m
---
apiVersion: v1
kind: Service
metadata:
  name: logstash-cloud
  namespace: $NAMESPACE
spec:
  selector:
    logstash.k8s.elastic.co/name: logstash-cloud
  ports:
  - name: beats
    port: 5044
    targetPort: 5044
  - name: http
    port: 8080
    targetPort: 8080
EOF
    
    log_success "Logstash deployed"
}

# Deploy Enterprise Search for Elastic Cloud
deploy_enterprise_search_cloud() {
    log_info "Deploying Enterprise Search for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: enterprisesearch.k8s.elastic.co/v1
kind: EnterpriseSearch
metadata:
  name: enterprise-search-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 1
  config:
    elasticsearch.host: "\${ELASTIC_CLOUD_URL}"
    elasticsearch.api_key: "\${ELASTIC_CLOUD_API_KEY}"
    allow_es_settings_modification: true
    ent_search.external_url: "https://enterprise-search.local"
    kibana.external_url: "https://kibana.local"
  podTemplate:
    spec:
      containers:
      - name: enterprise-search
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
        resources:
          requests:
            memory: 4Gi
            cpu: 1000m
          limits:
            memory: 6Gi
            cpu: 2000m
EOF
    
    log_success "Enterprise Search deployed"
}

# Deploy Maps Server for Elastic Cloud
deploy_maps_server_cloud() {
    log_info "Deploying Elastic Maps Server for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: maps.k8s.elastic.co/v1alpha1
kind: ElasticMapsServer
metadata:
  name: maps-server-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 1
  config:
    elasticsearch.hosts: ["\${ELASTIC_CLOUD_URL}"]
    elasticsearch.api_key: "\${ELASTIC_CLOUD_API_KEY}"
    server.host: "0.0.0.0"
    server.basePath: "/maps"
    logging.level: info
  podTemplate:
    spec:
      containers:
      - name: maps
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
        resources:
          requests:
            memory: 2Gi
            cpu: 500m
          limits:
            memory: 4Gi
            cpu: 1000m
EOF
    
    log_success "Maps Server deployed"
}

# Deploy all Beats for comprehensive monitoring
deploy_all_beats_for_cloud() {
    log_info "Deploying all Beats for comprehensive monitoring..."
    
    # Deploy Packetbeat for network monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: packetbeat-cloud
  namespace: $NAMESPACE
spec:
  type: packetbeat
  version: $STACK_VERSION
  config:
    packetbeat.interfaces.device: any
    packetbeat.protocols:
      dns:
        ports: [53]
      http:
        ports: [80, 8080, 8000, 5000, 8002]
      tls:
        ports: [443, 993, 995, 5223, 8443, 8883, 9243]
      mysql:
        ports: [3306]
      pgsql:
        ports: [5432]
      redis:
        ports: [6379]
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
    - add_kubernetes_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        hostNetwork: true
        dnsPolicy: ClusterFirstWithHostNet
        containers:
        - name: packetbeat
          securityContext:
            runAsUser: 0
            capabilities:
              add:
              - NET_ADMIN
              - NET_RAW
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
EOF

    # Deploy Auditbeat for security monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: auditbeat-cloud
  namespace: $NAMESPACE
spec:
  type: auditbeat
  version: $STACK_VERSION
  config:
    auditbeat.modules:
    - module: file_integrity
      paths:
      - /bin
      - /usr/bin
      - /sbin
      - /usr/sbin
      - /etc
    - module: system
      datasets:
      - host
      - login
      - package
      - process
      - socket
      - user
      period: 10s
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_host_metadata: {}
    - add_kubernetes_metadata: {}
  daemonSet:
    podTemplate:
      spec:
        hostNetwork: true
        hostPID: true
        dnsPolicy: ClusterFirstWithHostNet
        containers:
        - name: auditbeat
          securityContext:
            runAsUser: 0
            privileged: true
          volumeMounts:
          - name: bin
            mountPath: /hostfs/bin
            readOnly: true
          - name: usrbin
            mountPath: /hostfs/usr/bin
            readOnly: true
          - name: sbin
            mountPath: /hostfs/sbin
            readOnly: true
          - name: usrsbin
            mountPath: /hostfs/usr/sbin
            readOnly: true
          - name: etc
            mountPath: /hostfs/etc
            readOnly: true
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
        volumes:
        - name: bin
          hostPath:
            path: /bin
        - name: usrbin
          hostPath:
            path: /usr/bin
        - name: sbin
          hostPath:
            path: /sbin
        - name: usrsbin
          hostPath:
            path: /usr/sbin
        - name: etc
          hostPath:
            path: /etc
EOF

    # Deploy Heartbeat for uptime monitoring
    cat <<EOF | kubectl apply -f -
apiVersion: beat.k8s.elastic.co/v1beta1
kind: Beat
metadata:
  name: heartbeat-cloud
  namespace: $NAMESPACE
spec:
  type: heartbeat
  version: $STACK_VERSION
  config:
    heartbeat.monitors:
    - type: http
      id: kubernetes-api
      name: "Kubernetes API Server"
      urls: ["https://kubernetes.default:443/healthz"]
      schedule: "@every 30s"
      check.response.status: [200]
    - type: tcp
      id: elasticsearch-tcp
      name: "Elasticsearch TCP"
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      schedule: "@every 30s"
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    processors:
    - add_cloud_metadata: {}
    - add_kubernetes_metadata: {}
  deployment:
    replicas: 1
    podTemplate:
      spec:
        containers:
        - name: heartbeat
          env:
          - name: ELASTIC_CLOUD_URL
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: url
          - name: ELASTIC_CLOUD_API_KEY
            valueFrom:
              secretKeyRef:
                name: elastic-cloud-credentials
                key: api-key
EOF
    
    log_success "All Beats deployed for comprehensive monitoring"
}

# Deploy APM Server for Elastic Cloud
deploy_apm_server_cloud() {
    log_info "Deploying APM Server for Elastic Cloud..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: apm.k8s.elastic.co/v1
kind: ApmServer
metadata:
  name: apm-server-cloud
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 1
  config:
    output.elasticsearch:
      hosts: ["\${ELASTIC_CLOUD_URL}"]
      api_key: "\${ELASTIC_CLOUD_API_KEY}"
    apm-server:
      host: "0.0.0.0:8200"
      frontend:
        enabled: true
        rate_limit: 1000
        allow_origins: ["*"]
      auth:
        api_key:
          enabled: true
      data_streams:
        enabled: true
  podTemplate:
    spec:
      containers:
      - name: apm-server
        env:
        - name: ELASTIC_CLOUD_URL
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: url
        - name: ELASTIC_CLOUD_API_KEY
          valueFrom:
            secretKeyRef:
              name: elastic-cloud-credentials
              key: api-key
        resources:
          requests:
            memory: 1Gi
            cpu: 500m
          limits:
            memory: 2Gi
            cpu: 1000m
EOF
    
    log_success "APM Server deployed"
}

# Deploy comprehensive self-hosted stack (all components)
deploy_comprehensive_self_hosted_stack() {
    log_info "Deploying comprehensive self-hosted Elastic stack..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy Elasticsearch with all plugins
    cat <<EOF | kubectl apply -f -
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: elasticsearch-comprehensive
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  nodeSets:
  - name: master
    count: 3
    config:
      node.roles: ["master"]
      xpack.ml.enabled: true
      xpack.graph.enabled: true
      xpack.watcher.enabled: true
      xpack.security.enabled: true
      cluster.initial_master_nodes: ["elasticsearch-comprehensive-es-master-0", "elasticsearch-comprehensive-es-master-1", "elasticsearch-comprehensive-es-master-2"]
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 20Gi
        storageClassName: gp2
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 2Gi
              cpu: 1000m
            limits:
              memory: 4Gi
              cpu: 2000m
  - name: data
    count: 3
    config:
      node.roles: ["data", "ingest", "transform"]
      xpack.ml.enabled: true
      xpack.graph.enabled: true
      xpack.watcher.enabled: true
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 100Gi
        storageClassName: gp2
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 4Gi
              cpu: 2000m
            limits:
              memory: 8Gi
              cpu: 4000m
EOF
    
    # Wait for Elasticsearch to be ready
    if [[ "$WAIT" == "true" ]]; then
        log_info "Waiting for Elasticsearch to be ready..."
        kubectl wait --for=condition=Ready --timeout="$TIMEOUT" elasticsearch/elasticsearch-comprehensive -n "$NAMESPACE"
    fi
    
    # Deploy Kibana with all features
    cat <<EOF | kubectl apply -f -
apiVersion: kibana.k8s.elastic.co/v1
kind: Kibana
metadata:
  name: kibana-comprehensive
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 2
  elasticsearchRef:
    name: elasticsearch-comprehensive
  config:
    xpack.fleet.enabled: true
    xpack.encryptedSavedObjects.encryptionKey: "min-32-byte-long-strong-encryption-key"
    xpack.security.encryptionKey: "min-32-byte-long-strong-encryption-key"
    xpack.reporting.encryptionKey: "min-32-byte-long-strong-encryption-key"
    xpack.maps.enabled: true
    xpack.graph.enabled: true
    xpack.ml.enabled: true
    xpack.canvas.enabled: true
  podTemplate:
    spec:
      containers:
      - name: kibana
        resources:
          requests:
            memory: 2Gi
            cpu: 1000m
          limits:
            memory: 4Gi
            cpu: 2000m
EOF
    
    log_success "Comprehensive self-hosted stack deployed"
}

# Deploy StackConfigPolicy for advanced Elasticsearch management
deploy_stack_config_policies() {
    log_info "Deploying StackConfigPolicy for advanced Elasticsearch management..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: stackconfigpolicy.k8s.elastic.co/v1alpha1
kind: StackConfigPolicy
metadata:
  name: elastic-stack-config
  namespace: $NAMESPACE
spec:
  elasticsearch:
    clusterSettings:
      cluster.routing.allocation.awareness.attributes: "k8s_node_name"
      cluster.routing.allocation.awareness.force.k8s_node_name.values: "*"
      indices.recovery.max_bytes_per_sec: "100mb"
      cluster.routing.allocation.disk.threshold.enabled: true
      cluster.routing.allocation.disk.watermark.low: "85%"
      cluster.routing.allocation.disk.watermark.high: "90%"
      cluster.routing.allocation.disk.watermark.flood_stage: "95%"
  securityRoleMappings:
    kibana_admin:
      roles:
      - "kibana_admin"
      rules:
        field:
          username: "elastic"
    superuser:
      roles:
      - "superuser"
      rules:
        field:
          username: "elastic"
  snapshotRepositories:
    default-repo:
      type: fs
      settings:
        location: "/usr/share/elasticsearch/snapshots"
        compress: true
  snapshotLifecyclePolicies:
    daily-snapshots:
      schedule: "0 2 * * *"
      name: "<daily-snap-{now/d}>"
      repository: "default-repo"
      config:
        indices: ["*"]
        ignore_unavailable: false
        include_global_state: true
      retention:
        expire_after: "30d"
        min_count: 5
        max_count: 50
  indexLifecyclePolicies:
    default-policy:
      policy:
        phases:
          hot:
            actions:
              rollover:
                max_size: "50gb"
                max_age: "30d"
          warm:
            min_age: "30d"
            actions:
              allocate:
                number_of_replicas: 0
          cold:
            min_age: "90d"
            actions:
              allocate:
                number_of_replicas: 0
          delete:
            min_age: "365d"
  indexTemplates:
    logs-template:
      index_patterns:
      - "logs-*"
      template:
        settings:
          number_of_shards: 1
          number_of_replicas: 1
          index.lifecycle.name: "default-policy"
        mappings:
          properties:
            "@timestamp":
              type: "date"
            message:
              type: "text"
            log.level:
              type: "keyword"
  ingestPipelines:
    default:
      description: "Default ingest pipeline"
      processors:
      - set:
          field: "processed_timestamp"
          value: "{{_ingest.timestamp}}"
      - grok:
          field: "message"
          patterns:
          - "%{COMBINEDAPACHELOG}"
          ignore_failure: true
EOF
    
    log_success "StackConfigPolicy deployed"
}

# Deploy Elasticsearch Autoscaler
deploy_elasticsearch_autoscaler() {
    log_info "Deploying Elasticsearch Autoscaler..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: autoscaling.k8s.elastic.co/v1alpha1
kind: ElasticsearchAutoscaler
metadata:
  name: elasticsearch-autoscaler
  namespace: $NAMESPACE
spec:
  elasticsearchRef:
    name: elasticsearch-es
  policies:
  - name: data-nodes-policy
    roles:
    - "data"
    - "ingest"
    resources:
      nodeCount:
        min: 2
        max: 10
      cpu:
        min: 2
        max: 8
      memory:
        min: "4Gi"
        max: "16Gi"
      storage:
        min: "64Gi"
        max: "1Ti"
    deciders:
      proactive_storage:
        forecast_window: "30m"
      reactive_storage:
        forecast_window: "5m"
  - name: ml-nodes-policy
    roles:
    - "ml"
    resources:
      nodeCount:
        min: 0
        max: 5
      cpu:
        min: 2
        max: 8
      memory:
        min: "8Gi"
        max: "32Gi"
    deciders:
      reactive_storage:
        forecast_window: "10m"
EOF
    
    log_success "Elasticsearch Autoscaler deployed"
}

# Deploy security policies (PSP and Network Policies)
deploy_security_policies() {
    log_info "Deploying security policies..."
    
    # Deploy Pod Security Policy for ECK
    cat <<EOF | kubectl apply -f -
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: eck-operator-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: beats-agent-psp
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
    - 'NET_ADMIN'
    - 'NET_RAW'
    - 'SYS_ADMIN'
    - 'SYS_PTRACE'
    - 'SYS_RESOURCE'
    - 'AUDIT_CONTROL'
    - 'AUDIT_READ'
  volumes:
    - '*'
  hostNetwork: true
  hostPID: true
  hostIPC: false
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
EOF

    # Deploy Network Policies
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: elastic-operator-network-policy
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      control-plane: elastic-operator
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 9443
  egress:
  - {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: elasticsearch-network-policy
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      elasticsearch.k8s.elastic.co/cluster-name: elasticsearch-es
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          kibana.k8s.elastic.co/name: kibana-kb
    - podSelector:
        matchLabels:
          beat.k8s.elastic.co/name: metricbeat-cloud
    - podSelector:
        matchLabels:
          beat.k8s.elastic.co/name: filebeat-cloud
    ports:
    - protocol: TCP
      port: 9200
    - protocol: TCP
      port: 9300
  egress:
  - {}
EOF
    
    log_success "Security policies deployed"
}

# Deploy hot-warm-cold architecture for self-hosted
deploy_hot_warm_cold_architecture() {
    log_info "Deploying hot-warm-cold Elasticsearch architecture..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: elasticsearch.k8s.elastic.co/v1
kind: Elasticsearch
metadata:
  name: elasticsearch-hwc
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  nodeSets:
  - name: master
    count: 3
    config:
      node.roles: ["master"]
      xpack.ml.enabled: true
      cluster.initial_master_nodes: ["elasticsearch-hwc-es-master-0", "elasticsearch-hwc-es-master-1", "elasticsearch-hwc-es-master-2"]
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 20Gi
        storageClassName: gp2
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 2Gi
              cpu: 1000m
            limits:
              memory: 4Gi
              cpu: 2000m
  - name: hot
    count: 3
    config:
      node.roles: ["data_hot", "ingest", "transform"]
      node.attr.data: "hot"
      xpack.ml.enabled: true
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 100Gi
        storageClassName: gp2-ssd
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 8Gi
              cpu: 4000m
            limits:
              memory: 16Gi
              cpu: 8000m
  - name: warm
    count: 2
    config:
      node.roles: ["data_warm"]
      node.attr.data: "warm"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 500Gi
        storageClassName: gp2
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 4Gi
              cpu: 2000m
            limits:
              memory: 8Gi
              cpu: 4000m
  - name: cold
    count: 2
    config:
      node.roles: ["data_cold"]
      node.attr.data: "cold"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 1Ti
        storageClassName: gp2-cold
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 2Gi
              cpu: 1000m
            limits:
              memory: 4Gi
              cpu: 2000m
  - name: ml
    count: 1
    config:
      node.roles: ["ml", "remote_cluster_client"]
      node.attr.ml.machine_memory: "17179869184"
      node.attr.ml.max_open_jobs: "20"
    volumeClaimTemplates:
    - metadata:
        name: elasticsearch-data
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 50Gi
        storageClassName: gp2
    podTemplate:
      spec:
        containers:
        - name: elasticsearch
          resources:
            requests:
              memory: 16Gi
              cpu: 8000m
            limits:
              memory: 32Gi
              cpu: 16000m
EOF
    
    log_success "Hot-warm-cold architecture deployed"
}

# Deploy advanced multi-pipeline Logstash
deploy_advanced_logstash() {
    log_info "Deploying advanced multi-pipeline Logstash..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: logstash.k8s.elastic.co/v1alpha1
kind: Logstash
metadata:
  name: logstash-advanced
  namespace: $NAMESPACE
spec:
  version: $STACK_VERSION
  count: 3
  elasticsearchRefs:
  - name: elasticsearch-es
    clusterName: elasticsearch
  config:
    pipeline.workers: 4
    pipeline.batch.size: 1000
    pipeline.batch.delay: 50
    queue.type: persisted
    queue.max_bytes: "1gb"
    queue.checkpoint.writes: 1024
    dead_letter_queue.enable: true
    dead_letter_queue.max_bytes: "1gb"
    log.level: info
    xpack.monitoring.enabled: true
  pipelines:
  - pipeline.id: beats
    config.string: |
      input {
        beats {
          port => 5044
        }
      }
      filter {
        if [fields][logstash_format] == "docker" {
          json {
            source => "message"
          }
          date {
            match => [ "timestamp", "ISO8601" ]
          }
        }
        mutate {
          add_field => { "pipeline" => "beats" }
          add_field => { "processed_timestamp" => "%{@timestamp}" }
        }
      }
      output {
        elasticsearch {
          hosts => ["https://elasticsearch-es-http:9200"]
          user => "elastic"
          password => "${ELASTIC_PASSWORD}"
          index => "beats-%{+YYYY.MM.dd}"
          ssl => true
          ssl_certificate_verification => false
        }
      }
  - pipeline.id: http
    config.string: |
      input {
        http {
          port => 8080
          codec => json
        }
      }
      filter {
        mutate {
          add_field => { "pipeline" => "http" }
          add_field => { "received_timestamp" => "%{@timestamp}" }
        }
        if [level] {
          mutate {
            rename => { "level" => "log.level" }
          }
        }
      }
      output {
        elasticsearch {
          hosts => ["https://elasticsearch-es-http:9200"]
          user => "elastic"
          password => "${ELASTIC_PASSWORD}"
          index => "http-logs-%{+YYYY.MM.dd}"
          ssl => true
          ssl_certificate_verification => false
        }
      }
  - pipeline.id: deadletter
    config.string: |
      input {
        dead_letter_queue {
          path => "/usr/share/logstash/data/dead_letter_queue"
          commit_offsets => true
        }
      }
      output {
        elasticsearch {
          hosts => ["https://elasticsearch-es-http:9200"]
          user => "elastic"
          password => "${ELASTIC_PASSWORD}"
          index => "deadletter-%{+YYYY.MM.dd}"
          ssl => true
          ssl_certificate_verification => false
        }
      }
  volumeClaimTemplates:
  - metadata:
      name: logstash-data
    spec:
      accessModes:
      - ReadWriteOnce
      resources:
        requests:
          storage: 10Gi
      storageClassName: gp2
  podTemplate:
    spec:
      containers:
      - name: logstash
        env:
        - name: ELASTIC_PASSWORD
          valueFrom:
            secretKeyRef:
              name: elasticsearch-es-elastic-user
              key: elastic
        volumeMounts:
        - name: logstash-data
          mountPath: /usr/share/logstash/data
        resources:
          requests:
            memory: 4Gi
            cpu: 2000m
          limits:
            memory: 8Gi
            cpu: 4000m
---
apiVersion: v1
kind: Service
metadata:
  name: logstash-advanced
  namespace: $NAMESPACE
spec:
  selector:
    logstash.k8s.elastic.co/name: logstash-advanced
  ports:
  - name: beats
    port: 5044
    targetPort: 5044
  - name: http
    port: 8080
    targetPort: 8080
EOF
    
    log_success "Advanced multi-pipeline Logstash deployed"
}

# Deploy cloud provider specific ingress
deploy_cloud_provider_ingress() {
    if [[ -n "$CLOUD_PROVIDER" && "$DEPLOY_INGRESS" == "true" ]]; then
        case "$CLOUD_PROVIDER" in
            "aws")
                deploy_aws_alb_ingress
                ;;
            "gcp")
                deploy_gcp_ingress
                ;;
            "azure")
                deploy_azure_ingress
                ;;
            *)
                log_warning "Unknown cloud provider: $CLOUD_PROVIDER, using default nginx ingress"
                ;;
        esac
    fi
}

# Deploy AWS ALB Ingress
deploy_aws_alb_ingress() {
    log_info "Deploying AWS ALB ingress for Elasticsearch..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elasticsearch-alb-ingress
  namespace: $NAMESPACE
  annotations:
    alb.ingress.kubernetes.io/scheme: "internet-facing"
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/backend-protocol: "HTTPS"
    alb.ingress.kubernetes.io/target-type: "ip"
    alb.ingress.kubernetes.io/ssl-redirect: "443"
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID"
spec:
  ingressClassName: alb
  rules:
  - host: "elasticsearch.company.dev"
    http:
      paths:
      - path: "/"
        pathType: Prefix
        backend:
          service:
            name: elasticsearch-es-http
            port:
              number: 9200
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana-alb-ingress
  namespace: $NAMESPACE
  annotations:
    alb.ingress.kubernetes.io/scheme: "internet-facing"
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/backend-protocol: "HTTPS"
    alb.ingress.kubernetes.io/target-type: "ip"
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID"
spec:
  ingressClassName: alb
  rules:
  - host: "kibana.company.dev"
    http:
      paths:
      - path: "/"
        pathType: Prefix
        backend:
          service:
            name: kibana-kb-http
            port:
              number: 5601
EOF
    
    log_success "AWS ALB ingress deployed"
    log_info "Update the certificate ARN and host names in the ingress resources"
}

# Deploy GCP Ingress
deploy_gcp_ingress() {
    log_info "Deploying GCP Load Balancer ingress..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elasticsearch-gcp-ingress
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: "gce"
    kubernetes.io/ingress.global-static-ip-name: "elastic-ip"
    networking.gke.io/managed-certificates: "elastic-ssl-cert"
    kubernetes.io/ingress.allow-http: "false"
spec:
  rules:
  - host: "elasticsearch.company.dev"
    http:
      paths:
      - path: "/*"
        pathType: ImplementationSpecific
        backend:
          service:
            name: elasticsearch-es-http
            port:
              number: 9200
---
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: elastic-ssl-cert
  namespace: $NAMESPACE
spec:
  domains:
  - "elasticsearch.company.dev"
  - "kibana.company.dev"
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana-gcp-ingress
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: "gce"
    kubernetes.io/ingress.global-static-ip-name: "kibana-ip"
    networking.gke.io/managed-certificates: "elastic-ssl-cert"
spec:
  rules:
  - host: "kibana.company.dev"
    http:
      paths:
      - path: "/*"
        pathType: ImplementationSpecific
        backend:
          service:
            name: kibana-kb-http
            port:
              number: 5601
EOF
    
    log_success "GCP Load Balancer ingress deployed"
}

# Deploy Azure Ingress
deploy_azure_ingress() {
    log_info "Deploying Azure Application Gateway ingress..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elasticsearch-azure-ingress
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: azure/application-gateway
    appgw.ingress.kubernetes.io/ssl-redirect: "true"
    appgw.ingress.kubernetes.io/backend-protocol: "https"
    appgw.ingress.kubernetes.io/backend-hostname: "elasticsearch-es-http"
spec:
  tls:
  - hosts:
    - "elasticsearch.company.dev"
    secretName: elasticsearch-tls
  rules:
  - host: "elasticsearch.company.dev"
    http:
      paths:
      - path: "/"
        pathType: Prefix
        backend:
          service:
            name: elasticsearch-es-http
            port:
              number: 9200
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kibana-azure-ingress
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: azure/application-gateway
    appgw.ingress.kubernetes.io/ssl-redirect: "true"
    appgw.ingress.kubernetes.io/backend-protocol: "https"
spec:
  tls:
  - hosts:
    - "kibana.company.dev"
    secretName: kibana-tls
  rules:
  - host: "kibana.company.dev"
    http:
      paths:
      - path: "/"
        pathType: Prefix
        backend:
          service:
            name: kibana-kb-http
            port:
              number: 5601
EOF
    
    log_success "Azure Application Gateway ingress deployed"
}

# Run deployment
check_prerequisites
deploy