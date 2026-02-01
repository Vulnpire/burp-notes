# Burp Notes Extension (Java)

Burp Notes is a lightweight, offline note‑taking extension for Burp Suite. It adds per‑target Markdown notes, vulnerability checklists, cheatsheets, and attachments to help security testers keep structured engagement notes inside Burp.

## What it does

- Adds a Notes tab with a Markdown editor + preview, outline navigation, and attachments.
- Organizes notes per target (base domains only) with tags and checklist cards.
- Provides curated cheatsheets and recon/exploit info cards.
- Supports screenshot paste (Ctrl+V) with inline `{screenshot.png}` tokens rendered in preview.
- Imports/exports notes in Markdown or JSON for reporting.

## Features

- Per‑target notes with Markdown editor + preview (tables, task lists, fenced code blocks).
- Cheatsheets + tag‑based checklists with info cards (Identify / Recon / Exploit / Checklist).
- Tag management and tag‑based analytics.
- Screenshot paste stored as per‑target attachments.
- Inline screenshot tokens like `{screenshot_name.png}` rendered in preview.
- Attachments list with rename/remove.
- Detach notes into a separate window (editor + preview).
- Outline navigator for `#` headings with click‑to‑jump (toggle in Options).
- Search notes with line‑number results (Options → Search).
- Import notes from `.md` or `.json`.
- Export selected targets to Markdown or JSON.
- Lightweight background save queue and optional unloading of inactive targets.
- Dark/light theme auto‑detection.
- Cross‑platform (Windows/macOS/Linux).

## Installation (manual JAR)

1. Build the extension JAR (see Build).
2. In Burp: **Extensions → Installed → Add**.
3. Extension type: **Java**. Select `burp-notes.jar`.

## Build (manual)

1. Download the Burp extender API JAR or use the Burp Suite JAR.
2. Compile:

```
javac -cp /path/to/burp-extender-api.jar -d out src/burp/*.java
```

If you haven't created the output directory yet:

```
mkdir -p out
javac -cp /path/to/burp-extender-api.jar -d out src/burp/*.java
```

3. Create a JAR:

```
jar cf burp-notes.jar -C out .
```

Important: the first argument after `cf` is the output JAR name (not a `.java` file).

Tip: if you already have the Burp Suite JAR (e.g., `burpsuite_pro.jar`), you can use it instead:

```
javac -cp /path/to/burpsuite_pro.jar -d out src/burp/*.java
```

## Usage

- Select a target in **Options → Targets** (only base domains; subdomains are grouped).
- Write notes in **Notes → Editor** and use **Preview** for rendered Markdown.
- Use **Tags** to show checklist cards. Right‑click tags or checklist items to mark N/A.
- Use **Options → Search** to find text across targets and jump to line numbers.
- Use **Options → Import/Export** to move notes between projects.

## Data storage

- Notes, tags, checklists, and attachments are stored on disk in the storage directory.
- Default storage path: `~/.burp-notes` (Windows/macOS/Linux supported).
- You can change the storage directory in **Options → Settings**.
- You can delete per‑target data or wipe all stored data from **Options → Data management**.

## Privacy & network behavior

- Offline by default: no outbound network requests.
- No telemetry or third‑party APIs.
- Uses only local storage and Burp APIs.

## Compatibility

- Burp Suite Community/Professional (Java extension).
- Cross‑platform: Windows, macOS, Linux.

## Example notes

- Sample report‑style notes: `examples/example.com.md`
- A built‑in sample target (`example.com`) is included on first load to showcase formatting.
