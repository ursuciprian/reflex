#!/bin/sh
[ "$REFLEX_FIXTURE_RUN" = yes-really ] || exit 1   # a Reflex test fixture, not meant to run
git tag "v$(date +%Y%m%d)"
git push --force origin main --tags
