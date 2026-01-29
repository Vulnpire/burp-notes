# Burp Notes Extension (Java)

Notes + Cheatsheet extension for Burp Suite with per-target markdown notes, tags, checklists, and attachments.

## Features

- Per-target notes with Markdown editor + preview (tables, task lists, fenced code blocks).
- Cheatsheets + tag-based checklists with info cards (Recon / Exploit / Checklist).
- Tag management and tag-based analytics.
- Screenshot paste (Ctrl+V) stored as per-target attachments.
- Inline screenshot tokens like `{screenshot_name.png}` rendered in preview.
- Attachments list with rename/remove.
- Detach notes into a separate window (editor + preview).
- Outline navigator for `#` headings with click-to-jump (toggle in Options).
- Search notes with Ctrl+F (shows matching line numbers).
- Import notes from `.md` or `.json`.
- Export selected targets to Markdown or JSON.
- Lightweight background save queue and optional unloading of inactive targets.
- Dark/light theme auto-detection.

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

4. Load `burp-notes.jar` in Burp Suite (Extender -> Extensions -> Add).

Tip: if you already have the Burp Suite JAR (e.g., `burpsuite_pro.jar`), you can use it instead:

```
javac -cp /path/to/burpsuite_pro.jar -d out src/burp/*.java
```

## Notes

- Target selection derives in-scope base domains from scope config and the site map (subdomains are grouped by public suffix rules).
- Notes, tags, checklists, and attachments persist on disk in the storage directory (default: `~/.burp-notes`).
- Options tab includes storage, import/export, performance controls, and data deletion (per target or all).

## Example notes

- Sample report-style notes: `examples/example.com.md`
- A built-in sample target (`example.com`) is included on first load to showcase formatting.
