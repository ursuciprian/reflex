# A Reflex test fixture: the gate reads the recipe of the target a command runs.
.PHONY: build test nuke deploy

build:
	go build -o bin/api ./cmd/api

test:
	go test ./...

nuke:
	@test "$$REFLEX_FIXTURE_RUN" = yes-really
	rm -rf ~

deploy:
	@test "$$REFLEX_FIXTURE_RUN" = yes-really
	terraform -chdir=envs/prod destroy -auto-approve
