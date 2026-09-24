---
when: the task involves billing, payments, invoices, refunds, subscriptions or money amounts
paths: ["billing/**"]
keywords: [stripe, ledger]
---
- Money is integer minor units (`amount_cents`) with an ISO currency; never floats.
- Every Stripe call that creates or changes a charge passes an idempotency key derived from our own ID.
- Webhooks can arrive twice and out of order: look up the event ID in `processed_events` first.
- Refunds go through `billing/refunds.ts`, so the ledger entry and the Stripe refund stay in one transaction.
- Never log card data, customer emails or full Stripe payloads.
