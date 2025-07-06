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
METHOD="auto"
FORCE="false"
DELETE_NAMESPACE="false"
DELETE_CRDS="false"
DELETE_PVS="false"
TIMEOUT="300s"

# Help function
show_help() {
    cat << EOF
Elastic Cloud on Kubernetes (ECK) Destruction Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -m, --method <METHOD>       Destruction method: auto, helm, manifests, dev (default: auto)
    -n, --namespace <NAMESPACE> Operator namespace (default: elastic-system)
    --name <NAME>              Operator name (default: elastic-operator)
    --delete-namespace         Delete the operator namespace
    --delete-crds              Delete ECK Custom Resource Definitions
    --delete-pvs               Delete Persistent Volumes (WARNING: DATA LOSS)
    --force                    Skip confirmation prompts
    --timeout <TIMEOUT>        Timeout for waiting operations (default: 300s)
    -h, --help                 Show this help message

DESTRUCTION METHODS:
    auto        Auto-detect deployment method and clean up accordingly
    helm        Remove Helm releases
    manifests   Remove Kubernetes manifests
    dev         Remove development deployment

EXAMPLES:
    # Auto-detect and remove ECK operator
    $0

    # Force removal with all cleanup options
    $0 --force --delete-namespace --delete-crds

    # Remove specific Helm deployment
    $0 --method helm --namespace my-elastic-system

    # Remove with PV cleanup (WARNING: DATA LOSS)
    $0 --delete-pvs --force

WARNING:
    Using --delete-pvs will permanently delete all data stored in 
    Elasticsearch clusters. This action cannot be undone.
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

# Confirmation prompt
confirm() {
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi
    
    echo -en "${YELLOW}$1 (y/N): ${NC}"
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
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
    
    log_success "Prerequisites check passed"
}

# Detect deployment method
detect_method() {
    if [[ "$METHOD" != "auto" ]]; then
        return
    fi
    
    log_info "Auto-detecting deployment method..."
    
    # Check for Helm releases
    if command -v helm &> /dev/null; then
        if helm list -n "$NAMESPACE" | grep -q "$OPERATOR_NAME"; then
            METHOD="helm"
            log_info "Detected Helm deployment"
            return
        fi
        
        # Check for CRD-only Helm release
        if helm list -A | grep -q "elastic-operator-crds"; then
            METHOD="helm"
            log_info "Detected Helm deployment with separate CRDs"
            return
        fi
    fi
    
    # Check for StatefulSet (manifests or dev deployment)
    if kubectl get statefulset "$OPERATOR_NAME" -n "$NAMESPACE" &> /dev/null; then
        METHOD="manifests"
        log_info "Detected manifest/dev deployment"
        return
    fi
    
    log_warning "Could not detect deployment method, using manifests as fallback"
    METHOD="manifests"
}

# Remove Elastic Stack resources
remove_elastic_resources() {
    log_info "Removing Elastic Stack resources..."
    
    # Get all namespaces with ECK resources
    local namespaces
    namespaces=$(kubectl get namespace -o name | cut -d/ -f2)
    
    for ns in $namespaces; do
        log_info "Checking namespace: $ns"
        
        # Remove Elastic resources in order to respect dependencies
        local resource_types=("elasticmapsserver" "logstash" "beat" "apmserver" "agent" "kibana" "enterprisesearch" "elasticsearch")
        
        for resource_type in "${resource_types[@]}"; do
            local resources
            resources=$(kubectl get "$resource_type" -n "$ns" -o name 2>/dev/null || true)
            
            if [[ -n "$resources" ]]; then
                log_info "Removing $resource_type resources in namespace $ns"
                echo "$resources" | xargs -r kubectl delete -n "$ns" --timeout="$TIMEOUT"
            fi
        done
    done
    
    # Wait for finalizers to complete
    log_info "Waiting for resource cleanup to complete..."
    sleep 10
}

# Remove operator using Helm
remove_helm() {
    log_info "Removing ECK operator using Helm..."
    
    # Remove main operator release
    if helm list -n "$NAMESPACE" | grep -q "$OPERATOR_NAME"; then
        log_info "Removing Helm release: $OPERATOR_NAME"
        helm uninstall "$OPERATOR_NAME" -n "$NAMESPACE"
    fi
    
    # Remove ECK stack release if exists
    if helm list -n "$NAMESPACE" | grep -q "eck-stack"; then
        log_info "Removing ECK stack Helm release"
        helm uninstall eck-stack -n "$NAMESPACE"
    fi
    
    # Remove CRDs release if exists
    if helm list -A | grep -q "elastic-operator-crds"; then
        if confirm "Remove ECK CRDs Helm release? This will affect all ECK resources cluster-wide."; then
            log_info "Removing ECK CRDs Helm release"
            helm uninstall elastic-operator-crds
        fi
    fi
    
    log_success "Helm releases removed"
}

# Remove operator using manifests
remove_manifests() {
    log_info "Removing ECK operator using manifest deletion..."
    
    # Remove operator deployment
    if kubectl get statefulset "$OPERATOR_NAME" -n "$NAMESPACE" &> /dev/null; then
        log_info "Removing operator StatefulSet"
        kubectl delete statefulset "$OPERATOR_NAME" -n "$NAMESPACE" --timeout="$TIMEOUT"
    fi
    
    # Remove operator service account and RBAC
    log_info "Removing operator RBAC resources"
    kubectl delete serviceaccount "$OPERATOR_NAME" -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete clusterrole "elastic-operator" --ignore-not-found=true
    kubectl delete clusterrolebinding "elastic-operator" --ignore-not-found=true
    
    # Remove webhook configuration
    kubectl delete validatingwebhookconfig "elastic-webhook.k8s.elastic.co" --ignore-not-found=true
    
    # Remove services
    kubectl delete service -n "$NAMESPACE" -l "control-plane=elastic-operator" --ignore-not-found=true
    
    log_success "Operator manifests removed"
}

# Remove development deployment
remove_dev() {
    log_info "Removing development deployment..."
    
    # Check if we're in the project root
    if [[ -f "Makefile" ]]; then
        log_info "Using Makefile clean targets"
        OPERATOR_NAMESPACE="$NAMESPACE" make clean-k8s-cluster || true
    else
        log_warning "Makefile not found, falling back to manifest removal"
        remove_manifests
    fi
    
    log_success "Development deployment removed"
}

# Remove CRDs
remove_crds() {
    if [[ "$DELETE_CRDS" == "true" ]]; then
        if confirm "Delete ECK Custom Resource Definitions? This will affect ALL ECK resources cluster-wide."; then
            log_info "Removing ECK CRDs..."
            
            # Remove CRDs by label or name pattern
            kubectl delete crd -l "app.kubernetes.io/name=elastic-operator" --ignore-not-found=true
            
            # Remove specific CRDs if label selector doesn't work
            local crds=(
                "agents.agent.k8s.elastic.co"
                "apmservers.apm.k8s.elastic.co"
                "beats.beat.k8s.elastic.co"
                "elasticsearches.elasticsearch.k8s.elastic.co"
                "elasticsearchautoscalers.autoscaling.k8s.elastic.co"
                "enterprisesearches.enterprisesearch.k8s.elastic.co"
                "kibanas.kibana.k8s.elastic.co"
                "logstashes.logstash.k8s.elastic.co"
                "elasticmapsservers.maps.k8s.elastic.co"
                "stackconfigpolicies.stackconfigpolicy.k8s.elastic.co"
            )
            
            for crd in "${crds[@]}"; do
                kubectl delete crd "$crd" --ignore-not-found=true &
            done
            wait
            
            log_success "ECK CRDs removed"
        fi
    fi
}

# Remove persistent volumes
remove_persistent_volumes() {
    if [[ "$DELETE_PVS" == "true" ]]; then
        log_warning "WARNING: This will permanently delete all data stored in Elasticsearch clusters!"
        if confirm "Are you absolutely sure you want to delete all Persistent Volumes?"; then
            log_info "Removing Persistent Volumes..."
            
            # Find PVs related to ECK
            local pvs
            pvs=$(kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.claimRef.namespace}{" "}{.spec.claimRef.name}{"\n"}{end}' | grep -E "(elasticsearch|elastic)" || true)
            
            if [[ -n "$pvs" ]]; then
                echo "$pvs" | while read -r pv_name pv_ns pvc_name; do
                    if [[ -n "$pv_name" ]]; then
                        log_info "Removing PV: $pv_name (PVC: $pvc_name in $pv_ns)"
                        kubectl delete pv "$pv_name" --ignore-not-found=true
                    fi
                done
            fi
            
            # Also remove PVCs that might be left
            local namespaces
            namespaces=$(kubectl get namespace -o name | cut -d/ -f2)
            
            for ns in $namespaces; do
                local pvcs
                pvcs=$(kubectl get pvc -n "$ns" -o name 2>/dev/null | grep -E "(elasticsearch|elastic)" || true)
                if [[ -n "$pvcs" ]]; then
                    log_info "Removing PVCs in namespace: $ns"
                    echo "$pvcs" | xargs -r kubectl delete -n "$ns"
                fi
            done
            
            log_success "Persistent Volumes removed"
        fi
    fi
}

# Remove namespace
remove_namespace() {
    if [[ "$DELETE_NAMESPACE" == "true" ]]; then
        if kubectl get namespace "$NAMESPACE" &> /dev/null; then
            if confirm "Delete namespace '$NAMESPACE'? This will remove all resources in the namespace."; then
                log_info "Removing namespace: $NAMESPACE"
                kubectl delete namespace "$NAMESPACE" --timeout="$TIMEOUT"
                log_success "Namespace removed"
            fi
        fi
    fi
}

# Show remaining resources
show_remaining_resources() {
    log_info "Checking for remaining ECK resources..."
    
    # Check for remaining ECK resources
    local remaining=""
    
    # Check for Elastic Stack resources
    local resource_types=("elasticsearch" "kibana" "apmserver" "beat" "agent" "enterprisesearch" "logstash" "elasticmapsserver")
    for resource_type in "${resource_types[@]}"; do
        local count
        count=$(kubectl get "$resource_type" --all-namespaces --no-headers 2>/dev/null | wc -l || echo "0")
        if [[ "$count" -gt 0 ]]; then
            remaining="$remaining\n  - $count $resource_type resources"
        fi
    done
    
    # Check for operator pods
    local operator_pods
    operator_pods=$(kubectl get pods --all-namespaces -l "control-plane=elastic-operator" --no-headers 2>/dev/null | wc -l || echo "0")
    if [[ "$operator_pods" -gt 0 ]]; then
        remaining="$remaining\n  - $operator_pods operator pods"
    fi
    
    # Check for CRDs
    local crd_count
    crd_count=$(kubectl get crd -o name 2>/dev/null | grep -c "k8s.elastic.co" || echo "0")
    if [[ "$crd_count" -gt 0 ]]; then
        remaining="$remaining\n  - $crd_count ECK CRDs"
    fi
    
    if [[ -n "$remaining" ]]; then
        log_warning "Remaining ECK resources found:"
        echo -e "$remaining"
        log_info "Use --delete-crds and --force options for complete cleanup"
    else
        log_success "No ECK resources found - cleanup complete"
    fi
}

# Main destruction logic
destroy() {
    log_info "Starting ECK destruction..."
    log_info "Method: $METHOD"
    log_info "Namespace: $NAMESPACE"
    log_info "Operator Name: $OPERATOR_NAME"
    
    if [[ "$FORCE" != "true" ]]; then
        if ! confirm "Are you sure you want to remove the ECK operator and all Elastic Stack resources?"; then
            log_info "Operation cancelled"
            exit 0
        fi
    fi
    
    # Remove Elastic Stack resources first
    remove_elastic_resources
    
    # Remove operator based on method
    case "$METHOD" in
        "helm")
            remove_helm
            ;;
        "manifests")
            remove_manifests
            ;;
        "dev")
            remove_dev
            ;;
        *)
            log_error "Unknown destruction method: $METHOD"
            exit 1
            ;;
    esac
    
    # Remove additional resources if requested
    remove_persistent_volumes
    remove_crds
    remove_namespace
    
    log_success "ECK destruction completed!"
    
    # Show remaining resources
    show_remaining_resources
    
    log_info "If you want to redeploy ECK, run: ./deploy.sh"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--method)
            METHOD="$2"
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
        --delete-namespace)
            DELETE_NAMESPACE="true"
            shift
            ;;
        --delete-crds)
            DELETE_CRDS="true"
            shift
            ;;
        --delete-pvs)
            DELETE_PVS="true"
            shift
            ;;
        --force)
            FORCE="true"
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

# Validate method
if [[ "$METHOD" != "auto" && "$METHOD" != "helm" && "$METHOD" != "manifests" && "$METHOD" != "dev" ]]; then
    log_error "Invalid destruction method: $METHOD"
    log_error "Valid methods: auto, helm, manifests, dev"
    exit 1
fi

# Run destruction
check_prerequisites
detect_method
destroy