"""Self-contained HTML for the paste window. No external assets, ever."""

import html

STYLE = """
:root { color-scheme: light dark; --bg:#f5f5f4; --card:#fff; --ink:#1c1917;
  --muted:#78716c; --line:#e7e5e4; --accent:#0f766e; --accent-ink:#fff;
  --warn:#b45309; }
@media (prefers-color-scheme: dark) { :root { --bg:#1c1917; --card:#292524;
  --ink:#fafaf9; --muted:#a8a29e; --line:#44403c; --accent:#2dd4bf;
  --accent-ink:#042f2e; --warn:#fbbf24; } }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center;
  justify-content:center; background:var(--bg); color:var(--ink);
  font:15px/1.5 ui-sans-serif,-apple-system,Segoe UI,sans-serif; padding:24px; }
.card { width:100%; max-width:560px; background:var(--card); border-radius:14px;
  border:1px solid var(--line); padding:28px; box-shadow:0 8px 30px rgba(0,0,0,.08); }
h1 { margin:0 0 4px; font-size:20px; letter-spacing:-.01em; }
.sub { margin:0 0 20px; color:var(--muted); font-size:13px; }
dl { display:grid; grid-template-columns:auto 1fr; gap:6px 14px; margin:0 0 20px;
  font-size:13px; }
dt { color:var(--muted); }
dd { margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  word-break:break-all; }
label { display:block; font-size:13px; font-weight:600; margin-bottom:6px; }
textarea, input[type=password] { width:100%; padding:12px; border-radius:9px;
  border:1px solid var(--line); background:var(--bg); color:var(--ink);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:14px; }
textarea { min-height:96px; resize:vertical; }
.row { display:flex; gap:10px; margin-top:18px; }
button { flex:1; padding:12px; border-radius:9px; border:1px solid var(--line);
  background:var(--card); color:var(--ink); font-size:14px; font-weight:600;
  cursor:pointer; }
button.primary { background:var(--accent); color:var(--accent-ink);
  border-color:var(--accent); }
.note { margin-top:18px; font-size:12px; color:var(--muted); }
.warn { color:var(--warn); }
.check { display:flex; align-items:center; gap:8px; margin-top:12px;
  font-size:13px; color:var(--muted); }
.check input { width:auto; }
.field { margin-bottom:16px; }
.field label { display:flex; align-items:baseline; gap:8px; }
.field input, .field textarea { width:100%; padding:12px; border-radius:9px;
  border:1px solid var(--line); background:var(--bg); color:var(--ink);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:14px; }
.field textarea { resize:vertical; }
.as { margin-left:auto; font-weight:400; font-size:11px; color:var(--muted);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
.opt { font-weight:400; font-size:11px; color:var(--muted); }
.fhint { margin:6px 0 0; font-size:12px; color:var(--muted); }
.big { font-size:40px; line-height:1; margin-bottom:12px; }
"""


def _page(title: str, body: str) -> str:
    """Wrap body markup in the shared document shell."""
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex\">"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body><main class=\"card\">{body}</main></body></html>"
    )


def _row(term: str, value: str) -> str:
    """Return one definition-list row, or nothing when the value is empty."""
    if not value:
        return ""
    return f"<dt>{html.escape(term)}</dt><dd>{html.escape(value)}</dd>"


def _field_input(index: int, field: dict) -> str:
    """Render one labelled input for the paste form."""
    key = html.escape(field["name"])
    label = html.escape(field["label"])
    note = html.escape(field.get("hint") or "")
    optional = "" if field["required"] else ' <span class="opt">optional</span>'
    stored_as = html.escape(field["secret_name"])
    if field["kind"] == "multiline":
        box = (f'<textarea id="f{index}" name="field.{key}" rows="6"'
               ' spellcheck="false" autocapitalize="off" autocorrect="off"'
               ' autocomplete="off"></textarea>')
    elif field["kind"] == "text":
        box = (f'<input id="f{index}" name="field.{key}" type="text"'
               ' spellcheck="false" autocapitalize="off" autocorrect="off"'
               ' autocomplete="off">')
    else:
        box = (f'<input id="f{index}" name="field.{key}" type="password"'
               ' class="masked" spellcheck="false" autocomplete="new-password">')
    hint_markup = f'<p class="fhint">{note}</p>' if note else ""
    return (f'<div class="field"><label for="f{index}">{label}{optional}'
            f'<span class="as">{stored_as}</span></label>{box}{hint_markup}</div>')


def paste_form(request: dict) -> str:
    """Return the form a human fills in to hand over one or more secrets."""
    rows = "".join([
        _row("needed for", request["purpose"]),
        _row("goes to", request["target"]),
        _row("asked by", request["requested_by"]),
    ])
    inputs = "".join(_field_input(index, field)
                     for index, field in enumerate(request["fields"]))
    count = len(request["fields"])
    heading = ("An agent needs a secret" if count == 1
               else f"An agent needs {count} values")
    intro = html.escape(request.get("hint") or "")
    return _page(f"Paste {request['name']}", f"""
      <h1>{heading}</h1>
      <p class="sub">Stored on this machine only. The agent is told that it
      worked &mdash; never what you typed.</p>
      {f'<p class="sub">{intro}</p>' if intro else ""}
      <dl>{rows}</dl>
      <form method="post" action="/paste/{html.escape(request['token'])}"
            autocomplete="off">
        {inputs}
        <label class="check"><input type="checkbox" id="reveal"> show values</label>
        <div class="row">
          <button type="submit" name="action" value="cancel">Cancel</button>
          <button class="primary" type="submit" name="action" value="save">Save
          </button>
        </div>
      </form>
      <p class="note">Stored in your macOS Keychain. Close this tab when done.</p>
      <script>
        const reveal = document.getElementById('reveal');
        const boxes = document.querySelectorAll('.masked');
        const mask = () => boxes.forEach(box => {{
          box.type = reveal.checked ? 'text' : 'password';
        }});
        reveal.addEventListener('change', mask); mask();
        const first = document.querySelector('.field input, .field textarea');
        if (first) first.focus();
      </script>
    """)


def result(title: str, message: str, *, ok: bool = True) -> str:
    """Return the page shown after the form is submitted or a link is stale."""
    return _page(title, f"""
      <div class="big">{'&#10003;' if ok else '&#9888;'}</div>
      <h1>{html.escape(title)}</h1>
      <p class="sub{'' if ok else ' warn'}">{html.escape(message)}</p>
      <p class="note">You can close this tab.</p>
      <script>setTimeout(() => window.close(), 2500);</script>
    """)


def console(requests: list, backend: str, count: int) -> str:
    """Return the small status page served at /."""
    if requests:
        items = "".join(
            f"<dt>{html.escape(r['name'])}</dt>"
            f"<dd><a href=\"{html.escape(r['url'])}\">open paste form</a></dd>"
            for r in requests)
        body = f"<dl>{items}</dl>"
    else:
        body = "<p class=\"sub\">No secret is being requested right now.</p>"
    return _page("Secret Input Layer", f"""
      <h1>Secret Input Layer</h1>
      <p class="sub">Local broker on this machine. Store: {html.escape(backend)}
      &middot; {count} secret(s) held.</p>
      {body}
    """)
