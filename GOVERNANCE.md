# Governance

## Project Structure

Craton HSM is maintained by [Craton Software Company](https://github.com/craton-co) with contributions from the open-source community.

### Roles

**Maintainers** have full commit access and are responsible for:
- Reviewing and merging pull requests
- Triaging issues and security reports
- Release management and signing
- Architectural decisions

**Crypto reviewers** are maintainers with additional responsibility for:
- Reviewing changes to `src/crypto/`, `src/store/key_material.rs`, and `src/token/token.rs`
- Validating cryptographic correctness and side-channel resistance
- Approving changes to self-tests, DRBG, and key lifecycle code

**Contributors** are community members who submit pull requests, report issues, or participate in discussions.

### Current Maintainers

See [CODEOWNERS](.github/CODEOWNERS) for the current list of maintainers and their review responsibilities.

## Decision-Making Process

### Minor Changes

Bug fixes, documentation improvements, dependency updates, and small enhancements can be merged by any maintainer after code review approval.

### Significant Changes

Changes that affect the public API, security model, cryptographic implementations, or architectural design require:

1. **Issue or discussion**: Open a GitHub issue or discussion describing the change and its motivation
2. **Review by two maintainers**: At least two maintainers must approve the PR
3. **Crypto review**: Changes to cryptographic code require approval from a crypto reviewer
4. **Documentation update**: Affected docs must be updated in the same PR

### Breaking Changes

Changes that break the PKCS#11 ABI, change key serialization formats, or alter security behavior require:

1. All of the above, plus:
2. **CHANGELOG entry** with migration instructions
3. **Migration guide update** documenting the change
4. **Version bump** following semantic versioning

## Contribution Process

1. Fork the repository
2. Create a feature branch from `main`
3. Sign the [CLA](CLA.md) (one-time, via CLA Assistant bot)
4. Submit a pull request using the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
5. Address review feedback
6. Maintainer merges after approval

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed build, test, and code guidelines.

## Security Governance

- Security vulnerabilities are reported via [GitHub private advisories](https://github.com/craton-co/craton-hsm-core/security/advisories/new)
- Response timeline: 48h acknowledgment, 1 week assessment, 30 days fix target
- Security fixes are backported to all supported versions
- See [SECURITY.md](SECURITY.md) for full details

## Release Process

1. All tests pass on CI (multi-platform)
2. `cargo audit` and `cargo deny check` pass
3. CHANGELOG updated with version and date
4. Version bumped in `Cargo.toml`
5. Git tag created and signed
6. Release artifacts published with checksums
7. See [Release Signing](docs/release-signing.md) for signing procedures

## Versioning

Craton HSM follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes to PKCS#11 ABI or key formats
- **MINOR**: New features, new mechanisms, backward-compatible additions
- **PATCH**: Bug fixes, security patches, documentation updates

Pre-1.0 versions (current) may include breaking changes in minor releases, documented in the CHANGELOG.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1).

## License

Craton HSM is licensed under [Apache-2.0](LICENSE). All contributions are subject to the [CLA](CLA.md).
