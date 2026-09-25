#!/bin/sh
[ "$REFLEX_FIXTURE_RUN" = yes-really ] || exit 1   # a Reflex test fixture, not meant to run
DB=prod-orders
aws rds delete-db-instance --db-instance-identifier "$DB" --skip-final-snapshot
