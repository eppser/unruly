# unruly
#
# The eval discipline is only real if someone other than its author can run it.
# Until now the fixtures needed a sequence of docker commands, a hand-written
# JWT and four environment variables that existed only in one shell's history.
# These targets are that knowledge, written down and executable.

GO      ?= go
BINARY  ?= unruly
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

LAB_URL      := http://127.0.0.1:54321
# The same lab behind a Kong-shaped gateway, with a REAL GoTrue mounted where
# the managed product mounts it. LAB_URL is bare PostgREST at the root, which
# is the self-hosted layout; this is the managed one, and it is what makes the
# auth checks gradeable without a cloud project.
LAB_AUTH_URL := http://127.0.0.1:54327
HARDENED_URL := http://127.0.0.1:54331
MATRIX_URL   := http://127.0.0.1:54341

.PHONY: help saturation
help:
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- build

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/unruly

.PHONY: install
install: ## Install to GOPATH/bin
	$(GO) install -ldflags '$(LDFLAGS)' ./cmd/unruly

.PHONY: release
release: ## Cross-compile static binaries into dist/
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		[ "$$os" = windows ] && ext=".exe"; \
		echo "  $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			$(GO) build -ldflags '$(LDFLAGS)' \
			-o dist/$(BINARY)_$${os}_$${arch}$$ext ./cmd/unruly || exit 1; \
	done

.PHONY: release-check
release-check: release ## Verify the cross-compiled artifacts are what the README promises
	@# "Single static binary" and "the win is distribution" are requirements,
	@# and nothing verified them: the release path was never exercised by the
	@# audit, so a dependency that needs cgo, or a lost CGO_ENABLED=0, would
	@# have surfaced on release day rather than in CI.
	@fail=0; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		[ "$$os" = windows ] && ext=".exe"; \
		f="dist/$(BINARY)_$${os}_$${arch}$$ext"; \
		if [ ! -f "$$f" ]; then echo "  MISSING $$f"; fail=1; continue; fi; \
		size=$$(wc -c < "$$f"); \
		if [ "$$size" -lt 4000000 ]; then echo "  $$f is only $$size bytes"; fail=1; fi; \
		case "$$os" in \
		linux) \
			if command -v file >/dev/null 2>&1; then \
				if file -b "$$f" | grep -q "dynamically linked"; then \
					echo "  $$f is DYNAMICALLY linked: CGO_ENABLED=0 was lost, and the"; \
					echo "     binary now depends on the glibc of whatever built it"; \
					fail=1; \
				fi; \
			fi ;; \
		esac; \
		echo "  ok $$f ($$size bytes)"; \
	done; \
	if command -v file >/dev/null 2>&1; then :; else echo "  note: file(1) absent, static linkage unverified"; fi; \
	exit $$fail

# ---------------------------------------------------------------- checks

.PHONY: fmt vet lint
fmt: ## Format
	gofmt -w $(shell git ls-files '*.go' | xargs -n1 dirname | sort -u)

vet: ## Vet
	$(GO) vet ./...

lint: fmt vet ## Format and vet (rewrites files; for humans)

.PHONY: lint-check
lint-check: ## Verify formatting and vet WITHOUT rewriting anything
	@# CI must not rewrite the tree. A job that runs `gofmt -w` and then passes
	@# has hidden the diff it just made, and the next person to clone gets a
	@# repository that only looks formatted because a machine fixed it in
	@# passing. So CI checks and fails; `make lint` is the one that edits, and
	@# it is for a person who wants the edit.
	@# `gofmt -l` with no path argument reads STDIN and blocks forever. GOFILES
	@# was never defined here, so the first version of this target hung the
	@# build with no output at all — a check that cannot fail because it never
	@# finishes.
	@unformatted=$$(gofmt -l cmd internal); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi
	@$(GO) vet ./...

.PHONY: race
race: ## Offline suite under the race detector
	@# Deliberately offline: with UNRULY_LIVE=1 the remediation eval
	@# applies REVOKE to the lab fixture and every later eval in the same
	@# process sees an empty database. That is why `make eval` runs
	@# remediation last, after its own reset.
	$(GO) test -race -count=1 ./...

.PHONY: test
test: ## Offline tests only (no network, no fixtures, deterministic)
	@# UNRULY_LIVE is unset explicitly. The live evals are opt-in via that
	@# variable, so a caller who happens to have it exported turned this target
	@# into a live run — which then executed the graded evals BEFORE
	@# fixtures-reset and left probe rows behind, failing the real graded run
	@# later in `make ci` with a row-count mismatch that looked like a scanner
	@# bug. A target that describes itself as offline must be offline whatever
	@# the caller's environment says.
	UNRULY_LIVE= $(GO) test ./...

.PHONY: fixtures-pocketbase
fixtures-pocketbase: ## Provision the PocketBase ground-truth fixtures
	@# Two instances with THE SAME collection names: one deliberately
	@# vulnerable, one hardened. Same names in both is the point -- a hardened
	@# instance missing a name would 404 there and score clean for the wrong
	@# reason.
	@fixtures/pocketbase/setup.sh

.PHONY: fixtures-pocketbase-down
fixtures-pocketbase-down: ## Stop the PocketBase fixtures and delete their data
	@fixtures/pocketbase/setup.sh --down

.PHONY: eval-pocketbase
eval-pocketbase: ## Grade recall and precision against the PocketBase fixtures
	UNRULY_PB_LAB=1 $(GO) test ./backend/pocketbase/ -count=1 -v

.PHONY: eval-neon
eval-neon: ## Grade the Neon backend against its committed answer key, offline
	@# Replays fixtures/neon/transcript.json, recorded from the live Data API.
	@# No credential, no network, no quota: the recording is the lab, and
	@# re-recording is how a change in the backend becomes visible as a diff.
	$(GO) test ./backend/neon/ -count=1 -v

.PHONY: neon-prune
neon-prune: ## Delete the Neon lab's accumulated probe sessions
	@# The live evals sign in on every run and Neon Auth keeps a session row
	@# for each. The probe ACCOUNTS are fixed addresses so they do not
	@# accumulate, but the sessions do: 102 of them by the time anybody
	@# counted. Residue in a lab this project would report as a finding if it
	@# found it in someone else's project.
	@#
	@# Scoped to internal/neonfixture.ProbeAccounts and refuses an unscoped
	@# delete, because removing every session would sign the owner out of
	@# their own project. Verifies the fixture seed counts either side.
	@test -f .secrets/neon.env || \
		{ echo "need .secrets/neon.env (see fixtures/neon/README.md)"; exit 1; }
	set -a; . ./.secrets/neon.env; set +a; \
	 UNRULY_PRUNE=1 $(GO) test ./internal/neonfixture/ -count=1 -run PruneProbeSessionsAgainstTheLiveLab -v

.PHONY: eval-neon-live
eval-neon-live: ## Cross-check the Neon backend against the live lab
	@# Two implementations against the real Data API. internal/exploit rewrites
	@# the Neon Auth sequence from scratch and imports nothing from the scanner,
	@# so its agreement corroborates the measurement rather than repeating it.
	@# Read-only: the fixture's seed row counts are untouched.
	@test -f .secrets/neon.env || \
		{ echo "need .secrets/neon.env (see fixtures/neon/README.md)"; exit 1; }
	set -a; . ./.secrets/neon.env; set +a; \
	 UNRULY_LIVE=1 $(GO) test ./backend/neon/ -count=1 -run CrossCheck -v

.PHONY: eval-neon-binary
eval-neon-binary: ## Run the BINARY against the Neon lab, the way an operator would
	@# Every other Neon eval grades a stage. Four defects got past all of them
	@# because each was about REACHING the stage rather than about what it
	@# decided -- and the last one could not have been caught by a replay at
	@# all, because the recording cancelled out the very prefix that was wrong.
	@test -f .secrets/neon.env || \
		{ echo "need .secrets/neon.env (see fixtures/neon/README.md)"; exit 1; }
	set -a; . ./.secrets/neon.env; set +a; \
	 UNRULY_LIVE=1 $(GO) test ./internal/eval -count=1 -run NeonBinary -v

.PHONY: wordlists
wordlists: ## Regenerate the pinned wordlists and sync them into the binary
	python3 data/gen_wordlists.py
	cp data/relations.txt data/routines.txt data/pages.txt data/functions.txt internal/wordlist/
	@echo "regenerated; commit the .txt files so scans stay reproducible from the repo"

# ---------------------------------------------------------------- fixtures

.PHONY: fixtures-up
.PHONY: fixtures-pull
fixtures-pull: ## Pre-pull every fixture image, serially and with retries
	@# Docker Hub rate-limits anonymous pulls by source IP and GitHub's runners
	@# share theirs. `fixtures-up` starts five stacks back to back and compose
	@# pulls each stack's images in parallel, and that burst is what trips it:
	@# every CI run on this repository failed at "start fixtures" with
	@# "toomanyrequests: Rate exceeded" before a single test ran.
	@#
	@# Serialised and retried, because the burst limit recovers in seconds. A
	@# pull that still fails after the backoff is a real failure and stays one:
	@# retrying forever would turn a dead registry into a hung job.
	@for d in lab hardened matrix edge notsupabase; do \
		for attempt in 1 2 3 4 5; do \
			if COMPOSE_PARALLEL_LIMIT=1 docker compose -f fixtures/$$d/docker-compose.yml pull -q; then \
				break; \
			fi; \
			if [ $$attempt -eq 5 ]; then \
				echo "fixtures/$$d: image pull failed after 5 attempts"; exit 1; \
			fi; \
			echo "fixtures/$$d: pull failed, retrying in $$((attempt * 15))s"; \
			sleep $$((attempt * 15)); \
		done; \
	done

fixtures-up: ## Start every eval fixture and mint their JWTs
	@cd fixtures/lab && docker compose up -d --remove-orphans
	@cd fixtures/hardened && docker compose up -d
	@cd fixtures/matrix && docker compose up -d
	@cd fixtures/edge && docker compose up -d
	@cd fixtures/notsupabase && docker compose up -d
	@$(MAKE) --no-print-directory fixtures-wait
	@mkdir -p fixtures/lab/site
	@# A page that ships the service_role key to the browser, minted rather than
	@# committed: a JWT-shaped string in the tree trips the secret scan.
	@# Routes are discovered from the application's own markup, so the admin
	@# family has to be referenced here for the inconsistency check to see it.
	@./fixtures/lab/make-site.sh fixtures/lab/site/index.html
	@mkdir -p fixtures/lab/preview
	@# A DIFFERENT anon key from production's, so the preview finding takes its
	@# medium branch: a live credential a production rotation would not touch.
	@printf '<!doctype html><html><body><script>\nconst SUPABASE_URL="http://127.0.0.1:54321";\nconst SUPABASE_ANON_KEY="%s";\n</script></body></html>\n' \
		"$$(python3 fixtures/mint-jwt.py --sub 22222222-2222-2222-2222-222222222222)" > fixtures/lab/preview/index.html
	@mkdir -p fixtures/lab/archive
	@# One archived bundle per branch of the historic-key finding. b-current.js
	@# carries the SAME key the scan uses, which is the "removed from the bundle
	@# but never rotated" case; c-rotated.js carries a superseded one.
	@printf 'const SUPABASE_SERVICE_ROLE_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py --role service_role)" > fixtures/lab/archive/a-service.js
	@printf 'const SUPABASE_ANON_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py)" > fixtures/lab/archive/b-current.js
	@printf 'const SUPABASE_ANON_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py --sub 33333333-3333-3333-3333-333333333333)" > fixtures/lab/archive/c-rotated.js
	@# d-rotated-away.js is signed with a DIFFERENT secret, which is what
	@# rotation actually does. Without it the fixture cannot tell a rotated key
	@# from a live one -- every token it mints is accepted -- so the check that
	@# an archived credential still authenticates would pass whatever it was
	@# pointed at. It is the negative control for that technique.
	@printf 'const SUPABASE_ANON_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py --secret rotated-away-and-no-longer-valid-1234)" > fixtures/lab/archive/d-rotated-away.js
	@python3 fixtures/mint-jwt.py > fixtures/lab/anon.jwt
	@python3 fixtures/mint-jwt.py --role authenticated > fixtures/lab/authenticated.jwt
	@python3 fixtures/mint-jwt.py > fixtures/hardened/anon.jwt
	@python3 fixtures/mint-jwt.py --role authenticated \
		--sub 22222222-2222-2222-2222-222222222222 > fixtures/hardened/authenticated.jwt
	@python3 fixtures/mint-jwt.py > fixtures/matrix/anon.jwt
	@python3 fixtures/mint-jwt.py --role authenticated > fixtures/matrix/authenticated.jwt
	@echo "fixtures ready: lab $(LAB_URL), auth $(LAB_AUTH_URL), hardened $(HARDENED_URL), matrix $(MATRIX_URL)"

.PHONY: fixtures-wait
fixtures-wait:
	@for url in $(LAB_URL) $(LAB_AUTH_URL) $(HARDENED_URL) $(MATRIX_URL); do \
		printf "  waiting for %s " $$url; \
		for i in $$(seq 1 60); do \
			code=$$(curl -s -o /dev/null -w '%{http_code}' $$url --max-time 2 2>/dev/null); \
			if [ -n "$$code" ] && [ "$$code" != "000" ] && [ "$$code" != "503" ]; then echo "ok"; break; fi; \
			printf "."; sleep 1; \
			if [ $$i = 60 ]; then echo " TIMEOUT"; exit 1; fi; \
		done; \
	done

.PHONY: fixtures-check
fixtures-check: ## Fail fast, and legibly, when the fixtures are not serving
	@for url in $(LAB_URL) $(LAB_AUTH_URL) $(HARDENED_URL) $(MATRIX_URL); do \
		code=$$(curl -s -o /dev/null -w '%{http_code}' $$url --max-time 3 2>/dev/null); \
		if [ -z "$$code" ] || [ "$$code" = "000" ]; then \
			echo ""; \
			echo "  FIXTURE NOT REACHABLE: $$url"; \
			echo ""; \
			echo "  This is a broken test environment, not a scanner regression."; \
			echo "  Grading against a fixture that is not answering produces recall and"; \
			echo "  precision numbers that describe the harness, and this project has"; \
			echo "  lost time to that eleven times: a dead Docker daemon reads as"; \
			echo "  \"read-exposure-classifier is UNSOUND\" and \"probed 9 relations in 3ms\"."; \
			echo ""; \
			echo "    make fixtures-up          # start them"; \
			echo "    colima start -p lab       # if Docker itself is down"; \
			echo ""; \
			exit 1; \
		fi; \
	done

.PHONY: fixtures-edge
fixtures-edge: ## Start the real edge-runtime fixture (deployed + catch-all hosts)
	@cd fixtures/edge && docker compose up -d
	@printf "  waiting for edge-runtime "; \
	for i in $$(seq 1 60); do \
		code=$$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:54351/functions/v1/hello --max-time 2 2>/dev/null || echo 000); \
		if [ "$$code" = "200" ]; then echo "ok"; break; fi; \
		printf "."; sleep 1; \
	done

.PHONY: fixtures-down
fixtures-down: ## Stop EVERY fixture and delete its data
	@# All five compose projects, not the three that existed when this target
	@# was written. edge and notsupabase arrived later with their own
	@# prerequisites on the eval targets, so they started but were never
	@# stopped -- two projects left running after `make fixtures-down` reported
	@# success, holding ports 54351-54366.
	-@cd fixtures/lab && docker compose down -v
	-@cd fixtures/hardened && docker compose down -v
	-@cd fixtures/matrix && docker compose down -v
	-@cd fixtures/edge && docker compose down -v
	-@cd fixtures/notsupabase && docker compose down -v

# ---------------------------------------------------------------- evals

.PHONY: eval-fixtures
eval-fixtures: fixtures-reset fixtures-check ## Reset, then grade local recall + precision
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 UNRULY_FIXTURE_AUTHED_KEY=$$(cat fixtures/lab/authenticated.jwt) \
	 UNRULY_HARDENED_KEY=$$(cat fixtures/hardened/anon.jwt) \
	 UNRULY_HARDENED_AUTHED_KEY=$$(cat fixtures/hardened/authenticated.jwt) \
	 UNRULY_MATRIX_KEY=$$(cat fixtures/matrix/anon.jwt) \
	 UNRULY_MATRIX_AUTHED_KEY=$$(cat fixtures/matrix/authenticated.jwt) \
	 $(GO) test -count=1 ./internal/eval -run 'Fixture|Hardened|Matrix|Replay|Verb|ReadOnlyRelation|NestedJSON|ArbitrarySQL|Firebase|RemoteConfig|RefusingHost|SelfHostedLayout|ResolveRestPrefix|SelfHostedTarget|DeclaredAPI|Acquire|ProbeEmail|ProbeAccount|AnonymousSignIn|AuthSurfaceIsGraded|StorageSurfaceIsGraded|RealtimeSubscriptionIsReported|GraphQLBypassIsReported|ScanSummaryDistinguishes|SeverityFilterNever|RateLimitIsActually|ColumnBudgetSaysWhat|EveryRequestCarriesThe|NoRoutesStopsProbing|StorageClassifies|StorageNeverGuesses|SubdomainsFound|EveryDocumentedCommandParses|KnownGapsDoNotDeny|BenchmarkClaimMatches|ReadmeFixtureRequestCount|RequestAttributionSums|ReadmeNamesEveryBackend|Subdomain|Function|EveryRequestedOutput|EveryRemediationIsCommentOrSQL|WeakPassword|ContentIsRated|NothingIsDemoted|ThreatModel|StillCannotDistinguish|WriteOnlyRelation|TheFixPlanExecutesAgainstTheSchema|AgentSuppliedName|RoundTripsThroughAFile' -v

.PHONY: fixtures-notsupabase
fixtures-notsupabase: ## Start the negative-control hosts (not Supabase)
	@cd fixtures/notsupabase && docker compose up -d
	@printf "  waiting for decoys "; \
	for i in $$(seq 1 30); do \
		code=$$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:54364/ --max-time 2 2>/dev/null || echo 000); \
		if [ "$$code" != "000" ]; then echo "ok"; break; fi; \
		printf "."; sleep 1; \
	done

.PHONY: eval-exploit-local
eval-exploit-local: fixtures-check fixtures-edge ## Exploit the local fixture and cross-check the scan against it
	@# Write techniques mutate the fixture, so this resets around itself the way
	@# eval-remediation does. Every other lab eval grades the seed state.
	@$(MAKE) --no-print-directory fixtures-reset
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run LocalExploits -v
	@$(MAKE) --no-print-directory fixtures-reset

DIR ?= compare-out
TOOL ?= both

.PHONY: estate
estate: ## Summarise a scanned estate: data classes, volumes, regions
	@# Reads reports a scan already wrote and sends nothing to any target.
	@# -regions asks the management API about YOUR account, not about the
	@# projects being summarised.
	@$(GO) build -o estate ./cmd/estate
	@./estate -dir $(DIR) -tool $(TOOL) $(if $(REGIONS),-regions,)

.PHONY: benchmark
benchmark: ## Score the scanner against the corpus (brings each project up and down)
	@# Not part of `make audit`: it starts and stops fourteen docker stacks and
	@# takes minutes. It is the measurement behind the accuracy claim, so it is
	@# run deliberately and its output is committed.
	@$(GO) build -o benchmark-runner ./cmd/benchmark
	@$(GO) build -o unruly ./cmd/unruly
	@UNRULY_BENCH_ANON_KEY=$$(python3 fixtures/mint-jwt.py --role anon) \
	 UNRULY_BENCH_AUTH_KEY=$$(python3 fixtures/mint-jwt.py --role authenticated --sub 22222222-2222-2222-2222-222222222222) \
	 UNRULY_BENCH_AUTH_KEY_B=$$(python3 fixtures/mint-jwt.py --role authenticated --sub 33333333-3333-3333-3333-333333333333) \
	 UNRULY_BENCH_SERVICE_KEY=$$(python3 fixtures/mint-jwt.py --role service_role) \
	 ./benchmark-runner -unruly ./unruly -out benchmark/RESULTS.md

.PHONY: eval-exploit-firebase
eval-exploit-firebase: ## Exploit the Firebase lab and cross-check the scan against it
	@test -f .secrets/firebase-lab-config.json || \
		{ echo "need .secrets/firebase-lab-config.json (see FirebaseMap/lab/README.md)"; exit 1; }
	@# The web API key is NOT a secret -- Google documents it as public and it
	@# ships in every client bundle -- but it stays out of the tree anyway,
	@# because the repository's own scan refuses credential-shaped strings and
	@# a fixture is not a reason to make an exception.
	@UNRULY_LIVE=1 \
	 FIREBASE_LAB_API_KEY=$$(python3 -c "import json;print(json.load(open('.secrets/firebase-lab-config.json'))['apiKey'])") \
	 FIREBASE_LAB_APP_ID=$$(python3 -c "import json;print(json.load(open('.secrets/firebase-lab-config.json'))['appId'])") \
	 FIREBASE_LAB_PROJECT_NUMBER=$$(python3 -c "import json;print(json.load(open('.secrets/firebase-lab-config.json'))['projectNumber'])") \
	 $(GO) test -count=1 ./internal/eval -run 'Firebase(Exploits|Protected|AnonymousWrite|WriteProbeRemoves)|SuppliedNamesReachFirestore' -v

.PHONY: eval-coverage
eval-coverage: fixtures-up fixtures-check fixtures-edge ## Check every finding's emit site is actually EXECUTED by a test
	@# Depends on the fixtures. Without them the live evals skip, their emit
	@# sites never execute, and this target reports them as untested code —
	@# which is "the test did not run", not "the code is not covered". The
	@# distinction this whole project is about, in its own tooling.
	@# The textual rule in id_coverage_test.go asks whether an id is NAMED by a
	@# test. This asks whether the code that emits it ever runs. Both are kept:
	@# the textual one is cheap and offline and catches a finding with no test
	@# at all; this one is expensive and says whether the test does anything.
	@$(GO) build -o coveraudit ./cmd/coveraudit
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 UNRULY_FIXTURE_AUTHED_KEY=$$(cat fixtures/lab/authenticated.jwt) \
	 UNRULY_HARDENED_KEY=$$(cat fixtures/hardened/anon.jwt) \
	 UNRULY_HARDENED_AUTHED_KEY=$$(cat fixtures/hardened/authenticated.jwt) \
	 UNRULY_MATRIX_KEY=$$(cat fixtures/matrix/anon.jwt) \
	 UNRULY_MATRIX_AUTHED_KEY=$$(cat fixtures/matrix/authenticated.jwt) \
	 $(GO) test -count=1 -coverprofile=cover.out -coverpkg=./internal/...,./backend/...,./scan/... ./internal/... ./backend/... ./scan/... >/dev/null 2>&1 || true
	@# The test run's own exit code is deliberately ignored: a failing suite
	@# still produces a usable profile, and this target grades COVERAGE, not
	@# correctness. The suites themselves are graded by the other eval targets,
	@# which ci runs first.
	@./coveraudit -profile cover.out

.PHONY: eval-exitcode
eval-exitcode: fixtures-check ## Check the exit-code contract CI depends on
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 UNRULY_HARDENED_KEY=$$(cat fixtures/hardened/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run ExitCode -v

.PHONY: eval-templates
eval-templates: fixtures-check ## Execute the commented worked examples in every fix
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run RemediationTemplates -v

.PHONY: eval-redaction
eval-redaction: fixtures-check ## Confirm -redact removes real data and keeps the finding usable
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run Redaction -v

.PHONY: eval-notsupabase
eval-notsupabase: fixtures-check fixtures-notsupabase ## Require near-silence against hosts that are not Supabase
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 $(GO) test -count=1 ./internal/eval -run NotSupabase -v

.PHONY: eval-edge
eval-edge: fixtures-check fixtures-edge ## Grade the Edge Function surface against the real runtime
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run Edge -v

.PHONY: eval-determinism
eval-determinism: fixtures-check ## Diff repeated identical scans; requires byte-identical reports
	@# Both offline determinism tests, named rather than matched by prefix. The
	@# looser pattern -run Determinism also matches TestLiveDeterminism, which
	@# scans the cloud target -- and this target is part of `make ci`, which must
	@# not depend on somebody else's project being reachable.
	@#
	@# The refused-target case is listed because it is a DIFFERENT property: the
	@# first test grades a healthy fixture where every stage completes, and this
	@# row's description promises stability for repeated identical scans without
	@# qualifying which targets. A dead host is the second most common target
	@# there is, and it was graded nowhere until it was named here.
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval \
	 -run '^(TestDeterminismRepeatedScansAreByteIdentical|TestDeterminismHoldsWhenTheTargetRefuses)$$' -v

.PHONY: eval-cloud
eval-cloud: ## Grade against the cloud target (needs SUPABASE_ANON_KEY)
	@test -n "$$SUPABASE_ANON_KEY" || \
		{ echo "SUPABASE_ANON_KEY is not set; skipping the cloud eval"; exit 1; }
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 $(GO) test -count=1 ./internal/eval -run TestLive -v

.PHONY: fixtures-reset
fixtures-reset: ## Recreate mutable fixtures from seed data
	@# --remove-orphans throughout: a container whose service is deleted from
	@# the compose file is NOT removed by `down`, it stays in the project
	@# holding its ports and its memory. A storage-api container from an
	@# abandoned experiment sat there OOM-killed and two audit runs lost
	@# eval-fixtures and eval-exitcode to "fixture unreachable", which names
	@# the symptom and not the leftover.
	@# Both lab and matrix are mutated by scans: write probes insert rows, and
	@# applying the tool's own -fix output to a fixture (which is how the
	@# remediation is verified) changes its policies permanently. Only the
	@# hardened fixture is read-only in practice.
	@cd fixtures/lab && docker compose down -v --remove-orphans >/dev/null 2>&1 && docker compose up -d --remove-orphans
	@cd fixtures/matrix && docker compose down -v --remove-orphans >/dev/null 2>&1 && docker compose up -d --remove-orphans
	@$(MAKE) --no-print-directory fixtures-wait
	@mkdir -p fixtures/lab/site
	@# A page that ships the service_role key to the browser, minted rather than
	@# committed: a JWT-shaped string in the tree trips the secret scan.
	@# Routes are discovered from the application's own markup, so the admin
	@# family has to be referenced here for the inconsistency check to see it.
	@./fixtures/lab/make-site.sh fixtures/lab/site/index.html
	@mkdir -p fixtures/lab/preview
	@# A DIFFERENT anon key from production's, so the preview finding takes its
	@# medium branch: a live credential a production rotation would not touch.
	@printf '<!doctype html><html><body><script>\nconst SUPABASE_URL="http://127.0.0.1:54321";\nconst SUPABASE_ANON_KEY="%s";\n</script></body></html>\n' \
		"$$(python3 fixtures/mint-jwt.py --sub 22222222-2222-2222-2222-222222222222)" > fixtures/lab/preview/index.html
	@mkdir -p fixtures/lab/archive
	@# One archived bundle per branch of the historic-key finding. b-current.js
	@# carries the SAME key the scan uses, which is the "removed from the bundle
	@# but never rotated" case; c-rotated.js carries a superseded one.
	@printf 'const SUPABASE_SERVICE_ROLE_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py --role service_role)" > fixtures/lab/archive/a-service.js
	@printf 'const SUPABASE_ANON_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py)" > fixtures/lab/archive/b-current.js
	@printf 'const SUPABASE_ANON_KEY="%s";\n' \
		"$$(python3 fixtures/mint-jwt.py --sub 33333333-3333-3333-3333-333333333333)" > fixtures/lab/archive/c-rotated.js
	@python3 fixtures/mint-jwt.py > fixtures/lab/anon.jwt
	@python3 fixtures/mint-jwt.py --role authenticated > fixtures/lab/authenticated.jwt
	@python3 fixtures/mint-jwt.py > fixtures/matrix/anon.jwt
	@python3 fixtures/mint-jwt.py --role authenticated > fixtures/matrix/authenticated.jwt
	@echo "lab and matrix fixtures reset to seed state"

.PHONY: fixtures-wait-matrix
fixtures-wait-matrix:
	@printf "  waiting for %s " $(MATRIX_URL); \
	for i in $$(seq 1 60); do \
		code=$$(curl -sS -o /dev/null -w '%{http_code}' $(MATRIX_URL) --max-time 2 2>/dev/null || echo 000); \
		if [ "$$code" != "000" ] && [ "$$code" != "503" ]; then echo "ok"; break; fi; \
		printf "."; sleep 1; \
	done

.PHONY: eval-remediation
eval-remediation: fixtures-check ## Apply the tool's own -fix output and confirm the findings close
	@# Runs LAST and after its own reset: it applies remediation to the lab
	@# fixture, which permanently changes that fixture's policies. Every other
	@# lab eval grades against the seed state and would fail afterwards.
	@$(MAKE) --no-print-directory fixtures-reset
	@UNRULY_LIVE=1 UNRULY_CONCURRENCY=8 \
	 UNRULY_FIXTURE_KEY=$$(cat fixtures/lab/anon.jwt) \
	 $(GO) test -count=1 ./internal/eval -run Remediation -v
	@$(MAKE) --no-print-directory fixtures-reset

.PHONY: eval
eval: fixtures-up fixtures-reset eval-fixtures eval-edge eval-notsupabase eval-redaction eval-templates eval-exitcode eval-determinism eval-exploit-local eval-remediation ## Full local eval run, from nothing to graded

.PHONY: ci
ci: lint-check test fixtures-up fixtures-reset eval-fixtures eval-edge eval-notsupabase eval-redaction eval-templates eval-exitcode eval-determinism eval-coverage eval-exploit-local eval-remediation ## What CI runs

.PHONY: clean
clean: ## Remove build output
	rm -rf dist $(BINARY)

# Re-measure the concurrency default against a project you own. Opt-in: it puts
# real load on a real host. The end-to-end scan timings recorded in client.go
# are what actually chose the number; this checks the default has not drifted
# grossly off the plateau, and prints the curve.
#
#   make saturation SAT_URL=https://<ref>.supabase.co SAT_KEY=<anon key>
#
# UNRULY_SAT_COLD=1 reproduces the cold-pool artifact that made an earlier
# version of this sweep report the opposite of the truth.
.PHONY: ci-offline
ci-offline: ## Exactly what CI runs without Docker or credentials — check before pushing
	@# The offline job in .github/workflows/ci.yml, runnable locally. Two
	@# reasons it exists rather than being a comment in the workflow:
	@#
	@# The workflow had never executed. There is no remote, so every claim
	@# about "CI passes" was a claim about a file nobody had run -- the same
	@# never-executed-branch problem this project refuses everywhere else.
	@#
	@# And it keeps the two from drifting. A step added to the workflow that
	@# cannot run locally is a step contributors discover by pushing.
	go build ./...
	@$(MAKE) lint-check
	go vet ./...
	@$(MAKE) race
	@$(MAKE) test
	@$(MAKE) release-check
	@$(MAKE) mutation
	@echo "no committed credentials:"
	@if git grep -nIE 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.' -- . ':!*_test.go' ':!docs/*'; then \
		echo "  a JWT-shaped string is committed"; exit 1; \
	else echo "  clean"; fi

.PHONY: audit
audit: ## Reproduce every claim this project makes; see docs/auditing.md
	@scripts/audit.sh --out docs/audit-report.md

.PHONY: audit-offline
audit-offline: ## The part of the audit that needs no Docker and no credentials
	@scripts/audit.sh --offline --out docs/audit-report.md

.PHONY: coverage-offline
coverage-offline: ## Which finding sites does the suite miss WITHOUT Docker?
	@# eval-coverage answers the same question with the fixtures up. This one
	@# answers it without them, which is the more interesting question: a
	@# guarantee checked only by a fixture eval is checked only while the VM is
	@# alive, and the last three gaps found in this project were all that shape.
	@# Scope covers the WHOLE tree, not just internal/.
	@#
	@# It read ./internal/... alone, which was right while every finding was
	@# built there and silently stopped being right the moment the rebuild put
	@# emit sites in backend/. The finding-id scanner walks all of the source, so
	@# it correctly located backend/pocketbase/stage.go:75 and then reported it
	@# as never executed -- because the coverage PROFILE could not see the
	@# package that executes it. A guard scoped to a directory goes blind exactly
	@# when code moves, which is the third time this shape has appeared in this
	@# project.
	@go test ./internal/... ./backend/... ./scan/... -count=1 -coverprofile=cover-offline.out -coverpkg=./internal/...,./backend/...,./scan/... >/dev/null
	@go run ./cmd/coveraudit -profile cover-offline.out -root .
	@rm -f cover-offline.out

.PHONY: mutation
mutation: ## Break each decision the scanner makes and require a test to notice
	@python3 scripts/mutate.py

.PHONY: saturation
saturation:
	@test -n "$(SAT_URL)" || (echo "SAT_URL is required"; exit 1)
	@test -n "$(SAT_KEY)" || (echo "SAT_KEY is required"; exit 1)
	UNRULY_SATURATION=1 UNRULY_SAT_URL=$(SAT_URL) UNRULY_SAT_KEY=$(SAT_KEY) \
		go test ./internal/client/ -count=1 -run Saturation -v -timeout 30m
