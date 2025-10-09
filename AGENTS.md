# Repository Guidelines

## Project Structure & Module Organization
- `cmd/asset`, `cmd/cloudsploit`, `cmd/portscan`, `cmd/scc` hold service entrypoints and Docker build contexts; keep CLI wiring here only.
- `pkg/` provides reusable logic (e.g. `pkg/scc` for Security Command Center ingestion, `pkg/portscan` for scanning workflows, `pkg/common` for shared helpers, `pkg/grpc` and `pkg/sqs` for integration clients). Add new packages under `pkg/<feature>` with clear boundaries.
- `docs/` is for operator-facing references (see `docs/capability_ja.md`); mirror any new feature docs here.
- `hack/docker-build.sh` backs Makefile targets; avoid duplicating build scripts elsewhere.

## Build, Test, and Development Commands
- `make go-test`: runs `go generate ./...` and executes the full Go test suite.
- `make lint`: runs `golangci-lint` with the repo defaults; fix lint output before review.
- `make build IMAGE_TAG=<tag>`: executes tests then produces container images for each target via `hack/docker-build.sh`.
- `go run ./cmd/<service>`: run a service locally (e.g. `go run ./cmd/asset` for Asset inventory) using environment-configured credentials.

## Coding Style & Naming Conventions
- Format Go code with `gofmt` (tabs for indentation, PascalCase for exported symbols, camelCase for locals); `golangci-lint` enforces these conventions.
- Keep package names short and lowercase (`scc`, `cloudsploit`); file names use snake_case.
- Configuration files such as `cloudsploit.yaml` should follow existing key casing and comment style.

## Testing Guidelines
- Place unit tests alongside code in `pkg/<feature>/*_test.go`; follow table-driven patterns when asserting multiple scenarios.
- Mock external services (SQS, gRPC) with lightweight fakes or interfaces to keep tests hermetic.
- Run `make go-test` before pushing; include focused commands used for debugging (e.g. `go test ./pkg/scc -run TestFinding`) in PR notes when helpful.

## Commit & Pull Request Guidelines
- Use the existing `<type>: <summary>` convention (`fix:`, `update:`, `support:`) seen in `git log`; keep summaries under ~60 characters and reference issues when applicable.
- Group related changes per commit; avoid mixing code, vendor, and doc updates.
- Pull requests should describe intent, list core changes, and attach validation evidence (`make go-test`, `make lint`, manual run outputs). Link issues or incidents and add screenshots when modifying user-facing behaviour.

## Security & Configuration Tips
- Never commit credentials or project secrets; configure them via environment variables read by the services.
- Review IAM and GCP resource scopes before expanding collectors, and request a peer review when changing default permissions.
