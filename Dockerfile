FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG TARGETPLATFORM
COPY --chmod=0555 ${TARGETPLATFORM}/relay /relay
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/relay"]
CMD ["-config", "/etc/relay/config/config.json"]
