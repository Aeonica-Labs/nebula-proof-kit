# Contributing to Nebula Proof Kit

Thank you for your interest in contributing to nebula-proof-kit! This document provides guidelines for contributions.

## Code of Conduct

Be respectful and professional in all interactions.

## What We Accept

We welcome contributions that:

- **Fix bugs** in verification logic
- **Improve documentation** for clarity
- **Add test vectors** for edge cases
- **Enhance error messages** for better debugging
- **Add language bindings** (Go, Rust, Java, etc.)
- **Improve performance** of cryptographic operations

## What We Don't Accept

This is a **verification-only** toolkit. We do not accept:

- **Proof generation code** - This remains proprietary to NebulaGuard
- **Changes to proof format** - Format changes require coordination with production systems
- **Signing key material** - Never submit private keys

## How to Contribute

### 1. Report Bugs

Open an issue with:
- Proof JSON that fails verification unexpectedly
- Expected vs actual behavior
- Verifier version and environment

### 2. Submit Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Make your changes
4. Add tests if applicable
5. Run existing tests to ensure nothing breaks
6. Submit a PR with a clear description

### Pull Request Guidelines

- Keep changes focused and minimal
- Update documentation for any API changes
- Add test vectors for new validation rules
- Follow existing code style

## Development Setup

### TypeScript

```bash
cd packages/typescript
npm install
npm run build
npm test
```

### Python

```bash
cd packages/python
pip install -e ".[dev]"
pytest
```

### CLI

```bash
cd cli
npm install
npm run build
npm run dev -- verify ../test-vectors/valid/deletion_proof.json
```

## Test Vectors

When adding test vectors:

1. Place valid proofs in `test-vectors/valid/`
2. Place invalid proofs in `test-vectors/invalid/`
3. Include `_test_description` and `_expected_error` for invalid proofs
4. Update `test-vectors/README.md`

## Cryptographic Changes

Changes to cryptographic code require extra scrutiny:

- Reference the relevant RFC or standard
- Explain why the change is necessary
- Provide test vectors from official sources when available

## Questions?

- Open a GitHub issue for technical questions
- Email security@nebulaguard.net for security-related concerns

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
