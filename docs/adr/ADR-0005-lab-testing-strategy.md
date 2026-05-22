# ADR-0005: Lab-based testing strategy

Date: 2026-05-22
Status: Accepted

## Context
Synthetic log testing is useful but does not validate real agent pipelines or collection gaps. A lab with real agents will provide end-to-end validation.

## Decision
Validate rules in a lab using a Wazuh manager on Ubuntu, a Linux Mint agent, and a Windows agent. Add a Kali VM later for attack simulation. Keep the logtest runner optional.

## Consequences
- Tests validate real collection, decoders, and alerting.
- Setup is heavier than synthetic tests and requires VM access.
- Documentation must guide lab setup and trigger steps.
