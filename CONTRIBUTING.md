# Contributing

Thank you for your interest in contributing to this project. Please read [SUPPORT.md](SUPPORT.md) for the official support policy — this is a community-supported repository.

## Reporting Issues

- Search [existing issues](https://github.com/PaloAltoNetworks/prisma-cloud-scan/issues) before opening a new one.
- For bug reports, include: what you expected, what happened, the workflow configuration (redact secrets), and any relevant logs.
- For feature requests, describe the use case and why the current behavior doesn't meet your needs.

## Submitting Pull Requests

### Branch naming

Branch names determine how your PR is categorized in release notes:

| Branch prefix | Release notes category |
|---|---|
| `feature/...` | Features |
| `fix/...` | Bug Fixes |

### Workflow

1. Fork the repository and create a branch from `main` using the naming convention above.
2. Make your changes to `index.js` and/or other files.
3. Run the linter:
   ```bash
   npm run lint
   ```
4. Compile the distribution file — **this is required**:
   ```bash
   npm run build
   ```
5. Commit both `index.js` **and** `dist/index.js`. The action runs from `dist/index.js`, so PRs that omit the compiled output cannot be merged.
6. Open a pull request against `main` with a clear description of the change and motivation.

### Code standards

- All logic lives in `index.js` — do not create additional source files.
- Run `npm run lint` and resolve any ESLint errors before submitting.
- Keep changes focused. Avoid unrelated refactoring in the same PR.
- Boolean inputs must be checked against `TRUE_VALUES` (see existing usage in `index.js`).
- Proxy handling must go through `HttpsProxyAgent` — do not pass proxy config directly to axios.

### What makes a good PR

- A clear description of the problem and how the change solves it.
- Minimal scope — one concern per PR.
- `dist/index.js` regenerated via `npm run build`.
- Documentation updated in `README.md` if new inputs, outputs, or behaviors are added.

## Development Setup

```bash
npm install
npm run lint    # ESLint on index.js
npm run build   # Compile index.js → dist/index.js
```

Node.js 20 is required (matches the action runtime).
