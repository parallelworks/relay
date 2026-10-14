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

Release binaries, the image and the chart are built by the reusable workflow `.github/workflows/build.yml`, which signs them with Sigstore keyless signing and attests SLSA Build Level 3 provenance. The image also carries an SPDX SBOM attestation, and every release lists SPDX and CycloneDX SBOMs.

```sh
# A binary, against its provenance
gh attestation verify relay_linux_amd64 --repo parallelworks/relay \
  --signer-workflow parallelworks/relay/.github/workflows/build.yml

# The checksums file, against its signature
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/parallelworks/relay/.github/workflows/build.yml@refs/heads/canary' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksums.txt

# The image and the chart
gh attestation verify oci://ghcr.io/parallelworks/relay:<version> --repo parallelworks/relay \
  --signer-workflow parallelworks/relay/.github/workflows/build.yml
cosign verify ghcr.io/parallelworks/relay:<version> \
  --certificate-identity 'https://github.com/parallelworks/relay/.github/workflows/build.yml@refs/heads/canary' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/parallelworks/charts/relay:<version> \
  --certificate-identity 'https://github.com/parallelworks/relay/.github/workflows/build.yml@refs/heads/canary' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`go version -m relay` shows each binary's module versions and its FIPS 140-3 module (`GOFIPS140`).

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats the relay is designed against and the test that proves each mitigation.
