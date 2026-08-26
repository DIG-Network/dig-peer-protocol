# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.8.0] - 2026-08-26

### Chores
- **deps:** Adopt the chia-sdk-client 0.36.0 ceiling (#12)

## [0.7.0] - 2026-08-22

### Features
- **deps:** Uplift to chia-protocol 0.36.1 / chia-sdk-client 0.34 (#11)

## [0.6.0] - 2026-08-16

### Features
- **opcodes:** Assign 223/224/225 for profile-SMT sync (#9)

## [0.5.0] - 2026-08-11

### Features
- **rate-limit:** Public From<&RateLimits> for OpcodeRateLimits

## [0.4.0] - 2026-08-11

### Features
- **wire:** Standardize the DIG peer wire on native types, drop the chia bridge (#6)

## [0.3.0] - 2026-08-09

### Features
- **link:** DIG-owned websocket peer link framing DigMessage (#5)

## [0.2.1] - 2026-07-21

### Refactor
- **crate:** Rename dig-protocol -> dig-peer-protocol (#1383) (#4)

## [0.2.0] - 2026-07-19

### Features
- Add DIG_MESSAGE opcode const (220) for directed dig-message envelopes (#3)

## [0.1.2] - 2026-07-12

### Testing
- Cover the remaining decode/serde/error branches

### CI
- Add coverage gate failing under 80% line coverage- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#2)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

## [0.1.1] - 2026-04-16

### Documentation
- Expand README with full public API reference

## [0.1.0] - 2026-04-16


