# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's [private vulnerability reporting](https://github.com/parallelworks/relay/security/advisories/new). Do not open a public issue.

Include the affected version or commit, a description of the impact, and steps or a proof of concept that reproduce it.

We acknowledge reports within 3 business days and aim to release a fix for confirmed high or critical issues within 30 days. We publish a GitHub security advisory and request a CVE for every confirmed vulnerability, and credit reporters who want to be credited.

## Supported versions

Before 1.0, only the latest minor release receives security fixes. From 1.0, the latest two minor releases do.

## Scope

In scope: the relay binary, the `client` and `dpop` packages, the container image, the Helm chart, and the release artifacts and their provenance.

Out of scope: the authorization server, targets behind the relay, and deployments that change the chart's security settings.

## Verifying releases

Every release image and checksum file is signed with Sigstore keyless signing and carries SLSA build provenance:

```
gh attestation verify oci://ghcr.io/parallelworks/relay:<version> --repo parallelworks/relay
cosign verify ghcr.io/parallelworks/relay:<version> \
  --certificate-identity-regexp '^https://github.com/parallelworks/relay/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats the relay is designed against and the test that proves each mitigation.
