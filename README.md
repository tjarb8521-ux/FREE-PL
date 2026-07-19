---
title: Dadw
emoji: 🎮
colorFrom: red
colorTo: blue
sdk: gradio
sdk_version: 5.29.0
python_version: '3.12'
app_file: app.py
pinned: false
---

# 🎮 FREE-PL — Minecraft Server Control Panel

A Gradio-based web panel for managing a self-hosted **Purpur 1.21.1** Minecraft server, designed to run on **Hugging Face Spaces** (or locally).

## Features

- **Console** — live log viewer, send commands, start/stop/restart
- **File Manager** — browse, edit, create, rename, delete, upload, download
- **Settings** — edit `server.properties` through a GUI
- **User Management** — role-based access control (admin / editor / viewer)
- **System Monitoring** — CPU, RAM, disk, uptime, online players

---

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

The panel opens at **http://127.0.0.1:7860** by default.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AUTO_START_SERVER` | `false` | Set to `true` to automatically start the Minecraft server when the app launches. |
| `INITIAL_ADMIN_USERNAME` | *(empty)* | If set, this HF username is automatically added as `admin` in `users.json` on first run. |
| `ALLOW_FIRST_AUTHENTICATED_ADMIN` | `false` | If `true`, the **first** user who authenticates (via OAuth / proxy header) is promoted to `admin`. |

---

## Security

### Path Traversal Protection

Every file-manager operation (open, save, create, rename, delete, upload, download) goes through a set of safe-path helpers that guarantee the resolved path stays inside `WORKDIR` (`/home/user/app/server`):

| Helper | Purpose |
|---|---|
| `is_within_workdir(path)` | Returns `True` only if the absolute path is inside `WORKDIR`. |
| `normalize_relative_path(rel)` | Strips `..`, `//`, leading `/` from a relative path. |
| `validate_simple_name(name)` | Rejects names containing `/`, `\`, `.`, or `..`. |
| `resolve_safe_child_path(base, name)` | Combines a safe relative base with a child name and validates the result. |
| `sanitize_upload_name(name)` | Strips directory components from uploaded filenames. |

### Authentication & Permissions

The app extracts the current user from:

1. `gr.Request.username` (HF Spaces OAuth)
2. `X-Forwarded-User` header (reverse-proxy setups)
3. `?user=xxx` query parameter (fallback)

Roles and their permissions:

| Role | Permissions |
|---|---|
| `admin` | console, start, stop, restart, files_read, files_write, files_delete, users_manage |
| `editor` | console, files_read, files_write |
| `viewer` | console, files_read |

When no user is authenticated **and** `LOCAL_DEV_MODE` is `False`, all operations are denied by default.

---

## Project Structure

```
.
├── app.py              # Main application (Gradio UI + backend logic)
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── .gitignore
```

---

## License

This project is provided as-is for educational / personal use.
