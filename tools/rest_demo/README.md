# REST demo tool

`rest_demo` is a manifest-only REST tool. The process is the generic
`toolstack_forwarder`; it reads this `toolyard.toml`, verifies
`broker_channel`, and forwards named operations to `base_url`.

The checked-in `base_url` points at a placeholder loopback port. For a real
smoke, start a small upstream service, update `base_url`, set
`TOOLSTACK_TOOL_SECRET_REST_DEMO` plus `REST_DEMO_AUTH_TOKEN` in your secret
backend, then run:

```sh
toolyard up rest_demo --root tools
brokerctl reload
```

With the docker runner, REST tools without an explicit image use the toolyard's
generic forwarder fallback (`python:3.13-slim` with the repo mounted read-only).
