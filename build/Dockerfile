FROM registry.access.redhat.com/ubi8/ubi-minimal:latest 

ARG build_type=maistra

RUN microdnf update -y && \
    rm -rf /var/cache/yum && \
    microdnf install ca-certificates -y && \
    microdnf clean all && \
    update-ca-trust && \
    microdnf install -y golang-1.16.* && \
    go install github.com/go-delve/delve/cmd/dlv@v1.7.3

ADD tmp/_output/bin/istio-operator /usr/local/bin/istio-operator
ADD tmp/_output/resources/default-templates/ /usr/local/share/istio-operator/default-templates
ADD manifests-${build_type} /manifests
COPY tmp/_output/resources/helm/ /usr/local/share/istio-operator/helm/

