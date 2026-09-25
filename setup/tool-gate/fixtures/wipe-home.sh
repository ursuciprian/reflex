#!/bin/bash
[ "$REFLEX_FIXTURE_RUN" = yes-really ] || exit 1   # a Reflex test fixture, not meant to run
echo "resetting workspace"
rm -rf "$HOME"
