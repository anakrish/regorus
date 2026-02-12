# Cedar examples

This folder contains example Cedar policy sets and matching request/input data.

Quickstart

- Policy: examples/cedar/quickstart/policy.cedar
- Input: examples/cedar/quickstart/input.json
- Request: examples/cedar/quickstart/request.json
- Cedar CLI request: examples/cedar/quickstart/cedar_request.json
- Cedar CLI entities: examples/cedar/quickstart/cedar_entities.json

Run:

regorus cedar authorize -p examples/cedar/quickstart/policy.cedar --input examples/cedar/quickstart/input.json

Additional examples

- IAM / zero-trust: examples/cedar/examples/iam_zero_trust
- Cloud resource access: examples/cedar/examples/cloud_resource_access
- SaaS multi-tenant: examples/cedar/examples/saas_multi_tenant
- Regulated access: examples/cedar/examples/regulated_access
- Content system: examples/cedar/examples/content_system

Each example folder contains:
- policy.cedar
- input.json
- request.json
- entities.json
- cedar_request.json
- cedar_entities.json

Run any example:

regorus cedar authorize -p examples/cedar/examples/<name>/policy.cedar --input examples/cedar/examples/<name>/input.json

Run with Cedar CLI:

cedar authorize -p examples/cedar/examples/<name>/policy.cedar --request-json examples/cedar/examples/<name>/cedar_request.json --entities examples/cedar/examples/<name>/cedar_entities.json
