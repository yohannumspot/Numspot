#!/bin/bash

set -eo pipefail  # Stop script execution on error, including piped commands

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  -h, --help          Affiche cette aide et quitte.
  -c, --config FILE   Spécifie le fichier de configuration.

Config File Format: 

REGION='AAAA'
SERVICE_ACCOUNT_KEY='BBBB'
SERVICE_ACCOUNT_SECRET='CCCC'
SPACE_ID='DDDD'
CLUSTER_ID='EEEE'

EOF
    exit 0
}

main() {
    # Ask for Help
    if [[ "$2" == "-h" || "$2" == "--help" ]]; then
        usage
    fi

    # Check & Parse Configuration File

    if [[ "$2" == "-c" || "$2" == "--config" ]]; then

        CONFIG_FILE="$3"
        if [[ ! -f "$CONFIG_FILE" ]]; then
            error_exit "Configuration file '$CONFIG_FILE' not found!" 2    
        else
            source "$CONFIG_FILE"
        fi        
    else
        error_exit "No configuration specified" 2
    fi

    # Register cleanup handler
    trap cleanup EXIT INT TERM

    # Check required dependencies
    check_dependency "jq"
    check_dependency "curl"
    check_dependency "ssh"
    check_dependency "base64"

    # Check required variables
    check_variable "REGION"
    check_variable "SERVICE_ACCOUNT_KEY"
    check_variable "SERVICE_ACCOUNT_SECRET" true
    check_variable "SPACE_ID"
    check_variable "CLUSTER_ID"

    ENDPOINT="https://api.$REGION.numspot.com"
    KUBECONFIG_PATH="./kubeconfig-$CLUSTER_ID.yaml"
    PRIVATEKEY_PATH="./privatekey-$CLUSTER_ID.rsa"

    # Default timeout values
    API_TIMEOUT="${API_TIMEOUT:-30}"
    SSH_TIMEOUT="${SSH_TIMEOUT:-60}"

    ##############################################################################################
    
    log "INFO" "Retrieving Authentication Token."

    # Create auth credentials and get token
    AUTH_VALUE=$(echo -n "$SERVICE_ACCOUNT_KEY:$SERVICE_ACCOUNT_SECRET" | base64 -w 0 )

    RESPONSE=$(make_api_call "$ENDPOINT/iam/token" "POST" \
    --header="Content-Type: application/x-www-form-urlencoded" \
    --header="Authorization: Basic $AUTH_VALUE" \
    --data="grant_type=client_credentials&scope=openid+offline")

    # Extract and validate token
    TOKEN=$(echo "$RESPONSE" | jq -r .access_token 2>/dev/null)
    if [[ $? -ne 0 || "$TOKEN" == "null" || -z "$TOKEN" ]]; then
        error_exit "Invalid token response received: $RESPONSE" 4
    fi

    log "SUCCESS" "Token Successfully Retrieved"

    ##############################################################################################

    log "INFO" "Fetching cluster information."

    # Fetch cluster information
    CLUSTER_INFO=$(make_api_call "$ENDPOINT/kubernetes/spaces/$SPACE_ID/clusters/$CLUSTER_ID" "GET" \
    --header="Authorization: Bearer $TOKEN")

    # Extract and validate cluster info
    BASTION_IP=$(echo "$CLUSTER_INFO" | jq -r '.clientBastionPublicIP' 2>/dev/null)
    API_URL=$(echo "$CLUSTER_INFO" | jq -r '.apiUrl' 2>/dev/null)

    if [[ $? -ne 0 || "$BASTION_IP" == "null" || "$API_URL" == "null" ]]; then
        error_exit "Invalid cluster information received: $CLUSTER_INFO" 5
    fi

    log "SUCCESS"  "Cluster information retrieved / Bastion IP : $BASTION_IP - API URL : $API_URL"

    ##############################################################################################
    
    log "INFO" "Downloading & Patching Kubeconfig File."

    make_api_call "$ENDPOINT/kubernetes/spaces/$SPACE_ID/clusters/$CLUSTER_ID/kubeconfig" "GET" \
    --header="Authorization: Bearer $TOKEN" \
    --output="$KUBECONFIG_PATH"

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS (BSD sed)
        sed -i '' "s|$API_URL|127.0.0.1|g" $KUBECONFIG_PATH ||  error_exit "Failed to patch kubeconfig : $KUBECONFIG_PATH"
    else
        # Linux (GNU sed)
        sed -i "s|$API_URL|127.0.0.1|g" $KUBECONFIG_PATH || error_exit "Failed to patch kubeconfig : $KUBECONFIG_PATH"
    fi

    log "SUCCESS" "Kubeconfig downloaded and patched!"

    ##############################################################################################

    log "INFO" "Downloading Private Key File"
    
    make_api_call "$ENDPOINT/kubernetes/spaces/$SPACE_ID/clusters/$CLUSTER_ID/privatekey" "GET" \
    --header="Authorization: Bearer $TOKEN" \
    --output="$PRIVATEKEY_PATH"

    chmod 0600 $PRIVATEKEY_PATH || error_exit "Failed to to download private key" 

    log "SUCCESS" "Private Key Filed Downloaded."

    ##############################################################################################

    log "INFO"  "Adding Bastion Host to known_hosts."

    KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts"
    mkdir -p "$HOME/.ssh" 2>/dev/null || true
    chmod 700 "$HOME/.ssh" 2>/dev/null || true

    # Only add if not already there
    if ! grep -q "$BASTION_IP" "$KNOWN_HOSTS_FILE" 2>/dev/null; then
        if ! ssh-keyscan -T 10 "$BASTION_IP" >> "$KNOWN_HOSTS_FILE" 2>/dev/null; then
            error_exit "Failed to add Bastion Host to known_hosts!" 8
        fi
        chmod 600 "$KNOWN_HOSTS_FILE" 2>/dev/null || true
    fi

    log "SUCCESS"  "Bastion Host added to known_hosts"

    ##############################################################################################

    log "INFO" "Establishing SSH tunnel to bastion host."

    if [[ -f "$PRIVATEKEY_PATH" && -n "$BASTION_IP" && -n "$API_URL" ]]; then
        # SSH options for security and stability
        SSH_OPTIONS="-i $PRIVATEKEY_PATH -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"
        SSH_OPTIONS="$SSH_OPTIONS -o ConnectTimeout=$SSH_TIMEOUT -o ServerAliveInterval=30"
        SSH_OPTIONS="$SSH_OPTIONS -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes"
        
        ssh $SSH_OPTIONS -l client-tunnel -L 127.0.0.1:6443:$API_URL:6443 -N $BASTION_IP &
        SSH_PID=$!
        
        # Check if SSH process is still running after a brief delay
        sleep 2
        if ! kill -0 $SSH_PID 2>/dev/null; then
            error_exit "SSH tunnel failed to establish or terminated immediately" 9
        fi
        
        log "SUCCESS" "SSH tunnel established in background (PID: $SSH_PID, port 6443 → $API_URL:6443)"
        
        # Output connection instructions
        log "" ""
        log "" "To use kubectl with this cluster, run:"
        log "" "export KUBECONFIG=\"$PWD/$KUBECONFIG_PATH\""
        log "" "kubectl get nodes"

        wait $SSH_PID

    else
        error_exit "Cannot establish SSH tunnel"
    fi
}

# Cleanup on exit
cleanup() {
    if [[ -z "$CLEANUP_DONE" ]]; then
        # Kill any background SSH processes started by this script
        if [[ -n "$SSH_PID" ]]; then
            log "INFO" "Terminating SSH tunnel (PID: $SSH_PID)..."
            kill "$SSH_PID" 2>/dev/null || true
        fi

        log "SUCCESS" "Cleanup complete! Bye Bye 👋"
        CLEANUP_DONE=true
    fi
}

# Function for logging
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    case "$level" in
        "INFO")    echo "🔹 $timestamp - $message" ;;
        "ERROR")   echo "🛑 $timestamp - $message" >&2 ;;
        "SUCCESS") echo "✅ $timestamp - $message" ;;
        *) echo "$timestamp - $message" ;;
    esac
}

# Function to handle errors
error_exit() {
    log "ERROR" "$1"
    exit "${2:-1}"
}

# Check dependencies
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        error_exit "Required utility '$1' is not installed! Please install it and try again." 2
    fi
}

# Function to check if a variable is set
check_variable() {
    local var_name="$1"
    local var_value="${!var_name}"
    local is_secret="${2:-false}"
    
    if [[ -z "$var_value" ]]; then
        error_exit "Variable $var_name is empty! Set it in the environment or config file." 3
    elif [[ "$is_secret" != "true" ]]; then
        log "INFO" "Using $var_name: $var_value"
    else
        log "INFO" "Using $var_name: ********"
    fi
}

# Function to make API calls with error handling and timeouts

make_api_call() {
    local url="$1"
    local method="${2:-GET}"
    local output_file=""
    local data=""
    local headers=()
    
    # Parse the remaining arguments
    shift 2
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --output=*)
                output_file="${1#*=}"
                ;;
            --data=*)
                data="${1#*=}"
                ;;
            --header=*)
                headers+=("${1#*=}")
                ;;
            *)
                error_exit "Unknown parameter: $1"
                ;;
        esac
        shift
    done

    # Prepare curl command
    local curl_cmd=(curl --fail --silent --show-error --location-trusted --max-time "$API_TIMEOUT" --connect-timeout 10)
    
    # Add method if not GET
    [[ "$method" != "GET" ]] && curl_cmd+=(--request "$method")
    
    # Add headers
    for header in "${headers[@]}"; do
        curl_cmd+=(--header "$header")
    done
    
    # Make the API call with proper error handling
    local result=""
    if [[ -n "$output_file" ]]; then
        if ! "${curl_cmd[@]}" "$url" --output "$output_file"; then
            error_exit "API call failed - could not download to $output_file" 10
        fi
        if [[ ! -s "$output_file" ]]; then
            error_exit "API call returned empty file: $output_file" 11
        fi
    elif [[ -n "$data" ]]; then       
        local params
        IFS='&' read -ra params <<< "$data"
        
        for param in "${params[@]}"; do
             curl_cmd+=(--data-urlencode "$param")
        done
        
        if ! result=$("${curl_cmd[@]}" "$url"); then
             error_exit "API call failed - $result" 12
        fi
        echo "$result"
    else
        if ! result=$("${curl_cmd[@]}" "$url"); then
            error_exit "API call failed - $result" 13
        fi
        echo "$result"
    fi
}

main $# "$@"