# Tiny Neuron — Agent Action Control

**September series, Post 1:** From AI risk detection to agent action control.

This dependency-free Python reference implementation demonstrates a deterministic control point for a tool-using AI agent. Red teaming can expose unsafe behavior and observability can record it; this project makes an allow-or-deny decision before a tool executes.

## Controls
- Separate user and agent identities
- Deterministic policy evaluation outside the model
- Least-privilege, task-scoped authorization
- Deny-by-default tool gateway
- Structured audit events for allowed and denied decisions

## Demo cases
| Request | Expected decision |
| --- | --- |
| Support agent creates a bounded billing ticket | Allow |
| Support agent requests a bulk customer export | Deny |
| Retrieved text attempts to instruct the agent to export data | Deny |

## Run
```bash
python -m unittest discover -s tests -v
python -m app.demo
```

## Architecture
`User request -> Agent proposes tool action -> Policy engine -> Tool gateway -> Simulated tool`

This is an educational reference implementation. It contains no model call, production credentials, customer data, external API, or employer-specific logic.
