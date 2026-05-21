# Internal Formal Artifacts

Status: generated formal output index.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file indexes internal formal artifacts only.
Migrated from: the former hidden AFT formal artifact directory.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-05-02.

## Purpose

This directory holds curated generated formal outputs and compiled byproducts
that are useful for engineering review but should not sit beside canonical
architecture prose. Formal source lives under
`internal-docs/architecture/protocols/aft/formal/`; local proof-tool caches and
large model-checker scratch output live under ignored `.internal/formal-cache/`.

## Contents

- [`aft/`](./aft/) — curated AFT generated traces, selected TLC outputs, and compiled yellow paper outputs.
