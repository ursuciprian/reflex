---
when: the task changes Terraform or other infrastructure code, or runs infrastructure commands
paths: ["**/*.tf", "**/*.tfvars", "infra/**"]
keywords: [terraform, tofu]
---
- Always run `terraform plan -out tf.plan` first and summarise it as `X to add, Y to change, Z to destroy`; call out every destroy or replacement.
- Never run `apply` against `envs/prod`; open a PR and let CI apply it.
- Pin provider and module versions; no `latest`.
- State is remote (S3 + DynamoDB lock). Never edit state by hand or run `state rm` without asking.
