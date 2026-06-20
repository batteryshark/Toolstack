"""Toolstack broker: the authority boundary, and the only address an agent can reach.

One process with internal module seams: Gateway (ingress/egress), Identity (callers
+ hashed tokens), Policy (allow/review/deny), Registry-read, Request lifecycle,
Approval (orchestration + nod adapter), and Audit, over one SQLite file. It
authenticates callers, decides policy, routes review-required operations to a human
via nod, forwards approved calls to tools, and audits everything. The broker never
sees a workload secret. See ../plan.md and README.md.
"""
