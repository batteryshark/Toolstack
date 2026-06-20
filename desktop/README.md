# Toolstack desktop

A thin native window around the [admin control panel](../admin/README.md), so wiring up
callers and tools feels like an app, not a terminal session. It does **not** reimplement
anything: it starts the admin (which supervises the broker and runs tools), waits for it to
be healthy, and opens a native **OS-WebKit** window onto it. Close the window and the admin
this app started is stopped; an admin you already had running is left alone.

It uses [pywebview](https://pywebview.flowrl.com/): the operating system's own webview
(macOS WebKit / Linux WebKit2GTK / Windows WebView2), **not** a bundled Chromium, so the
shell stays tiny. The "slick" look comes from the admin UI itself (see [T-028]).

## Run

It's a deps-carrying component (like `admin`), so it runs from a venv that has the stack,
the admin's deps, and pywebview, not from the stdlib `pyproject`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[vault]' -r admin/requirements.txt -r desktop/requirements.txt
python3 -m admin set-password      # one-time: the admin won't serve without a password
python3 -m desktop                 # opens the window (starts the admin if it isn't up)
```

Inside the window: log in, click **Start broker**, then add a caller / author a tool / mint
a token, exactly as in the web admin. Point your agent at the broker on `127.0.0.1:8765`.

## What it manages

- **Lifecycle** (`desktop/app.py`, stdlib + unit-tested): `Stack.ensure_up()` is a no-op if
  the admin is already serving, else it starts `python -m admin serve`, waits for `/login`
  to answer, and surfaces the admin's own message if it exits early (e.g. no password set).
  `Stack.stop()` stops the admin **only if this app started it**.
- **Window** (pywebview, imported lazily): a single window onto the admin URL
  (`TOOLSTACK_ADMIN_URL`, default `http://127.0.0.1:8780`).

Loopback only: the window talks to the admin on `127.0.0.1`; nothing new is exposed.

## Packaging into a `.app` (later)

`python3 -m desktop` is the runnable shell. To ship a double-clickable bundle, wrap it with
[briefcase](https://briefcase.readthedocs.io/) or py2app; that's a distribution step, out of
scope here. For a heavier, more product-grade shell (system tray, `.dmg`, auto-update), the
Tauri path discussed on [T-027] remains an option to graduate to.

## Not yet

- Auto-starting the broker (today you click **Start broker** in the window, same as the web
  admin and the [Docker one-box](../deploy/docker/README.md)).
- A native first-run password dialog (today: the one-time `python3 -m admin set-password`).
