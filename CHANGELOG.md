# Changelog

## [0.1.2](https://github.com/parallelworks/relay/compare/v0.1.1...v0.1.2) (2026-10-21)


### Bug Fixes

* **deps:** build with Go 1.27.3, which distrusts eMudhra's compromised intermediate CAs ([#14](https://github.com/parallelworks/relay/issues/14)) ([db3fa56](https://github.com/parallelworks/relay/commit/db3fa56a4e0ff99297affd0b99c48ef0cd5b998b))

## [0.1.1](https://github.com/parallelworks/relay/compare/v0.1.0...v0.1.1) (2026-10-14)


### Bug Fixes

* **ci:** log in to the registry before pushing the release image ([#10](https://github.com/parallelworks/relay/issues/10)) ([c55f941](https://github.com/parallelworks/relay/commit/c55f9417c38a166f811a12ea1ed8b96819fdd717))
* **ci:** releases include the signature bundle for checksums.txt ([#12](https://github.com/parallelworks/relay/issues/12)) ([6254503](https://github.com/parallelworks/relay/commit/62545033644fbfb75efa4f6bec9598e134fd92a1))
* **ci:** republishing a release replaces its artifact notes instead of repeating them ([#13](https://github.com/parallelworks/relay/issues/13)) ([449be9d](https://github.com/parallelworks/relay/commit/449be9d6b856588b724fe0303d664e7ec482c51c))

## 0.1.0 (2026-10-14)


### Features

* DPoP proofs and egress policy ([#2](https://github.com/parallelworks/relay/issues/2)) ([ce7d772](https://github.com/parallelworks/relay/commit/ce7d772375060421d15447da7e242ab74624c512))
* telemetry, Helm chart, signed releases and the NIST 800-53 mapping ([#6](https://github.com/parallelworks/relay/issues/6)) ([14eca0c](https://github.com/parallelworks/relay/commit/14eca0c060140ca8fc6a20c08d08b0548f31f5ef))
* token introspection and relay registration ([#3](https://github.com/parallelworks/relay/issues/3)) ([f708483](https://github.com/parallelworks/relay/commit/f708483e327a9225768d094ceefd657fae4a61ba))
* tunnel client and the benchmark gate ([#5](https://github.com/parallelworks/relay/issues/5)) ([f40ce1e](https://github.com/parallelworks/relay/commit/f40ce1e35136b29ee0ae352207bfa9d3970cce3f))
* tunnels, sessions, the relay server and its binary ([#4](https://github.com/parallelworks/relay/issues/4)) ([cc8d7cd](https://github.com/parallelworks/relay/commit/cc8d7cd7ab1f161c1eb3740576db288dbe13da33))


### Bug Fixes

* an observer told a tunnel closed could still see its session open ([#8](https://github.com/parallelworks/relay/issues/8)) ([aa82e69](https://github.com/parallelworks/relay/commit/aa82e69c88b1c255255bd32d9d4120bb79ff6eae))
