FROM golang:1.15.6 AS builder

RUN mkdir /tmp/go

# Copy plugins source code
COPY SecretFromVault /tmp/go/SecretFromVault
COPY VaultReplaceInline /tmp/go/VaultReplaceInline
COPY ConfigMapFromVault /tmp/go/ConfigMapFromVault

# Compile kustomize plugins
WORKDIR /tmp/go/SecretFromVault
RUN CGO_ENABLED=0 GOOS=linux go build -o SecretFromVault SecretFromVault.go

WORKDIR /tmp/go/VaultReplaceInline
RUN CGO_ENABLED=0 GOOS=linux go build -o VaultReplaceInline VaultReplaceInline.go

WORKDIR /tmp/go/ConfigMapFromVault
RUN CGO_ENABLED=0 GOOS=linux go build -o ConfigMapFromVault ConfigMapFromVault.go

FROM argoproj/argocd:v1.8.1

# Switch to root for the ability to perform install
USER root

# Create plugins directories
RUN mkdir -p /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/secretsfromvault && \
    mkdir -p /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/vaultreplaceinline && \
    mkdir -p /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/configmapfromvault

# Copy plugins from builder image
COPY --from=builder /tmp/go/SecretFromVault/SecretFromVault /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/secretfromvault/
COPY --from=builder /tmp/go/VaultReplaceInline/VaultReplaceInline /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/vaultreplaceinline/
COPY --from=builder /tmp/go/ConfigMapFromVault/ConfigMapFromVault /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/configmapfromvault/

RUN chmod +x /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/secretfromvault/SecretFromVault && \
    chmod +x /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/vaultreplaceinline/VaultReplaceInline && \
    chmod +x /home/argocd/.config/kustomize/plugin/plugins.kustomize.com/v1/configmapfromvault/ConfigMapFromVault && \
    chown -R argocd. /home/argocd/.config

## Install tools needed for your repo-server to retrieve & decrypt secrets, render manifests
## (e.g. curl, awscli, gpg, sops)
RUN apt-get update && \
    apt-get install -y curl vim && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash && \
    mv -f kustomize /usr/local/bin/ && \
    chmod +x /usr/local/bin/kustomize

# Switch back to non-root user
USER argocd
