#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

# Determine GOBIN
GOBIN="${GOBIN:-$(go env GOPATH)/bin}"

# Install controller-gen if not present
if ! command -v controller-gen &> /dev/null && [ ! -f "${GOBIN}/controller-gen" ]; then
    echo "Installing controller-gen..."
    go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
fi

# Use controller-gen from GOBIN if not in PATH
CONTROLLER_GEN="${GOBIN}/controller-gen"
if command -v controller-gen &> /dev/null; then
    CONTROLLER_GEN="controller-gen"
fi

cd "${SCRIPT_ROOT}"

# Generate CRD manifests
echo "Generating CRD manifests..."
"${CONTROLLER_GEN}" crd \
    paths="./pkg/apis/k8s.cni.cncf.io/..." \
    output:crd:artifacts:config=.

# Rename the generated file to scheme.yml
mv k8s.cni.cncf.io_multi-networkpolicies.yaml scheme.yml

echo "Done."
