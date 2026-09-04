"""`sil` - the command line face of the secret input layer."""

import argparse
import getpass
import json
import sys

from . import __version__, config, daemon, fields, store
from .client import Client
from .errors import SilError


def _print(payload) -> None:
    """Print a JSON payload for humans and scripts alike."""
    print(json.dumps(payload, indent=2, sort_keys=True))


def _env_pairs(items) -> dict:
    """Turn --env VAR=secret arguments into a mapping."""
    mapping = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--env expects VAR=secret-name, got: {item}")
        var, name = item.split("=", 1)
        mapping[var] = name
    return mapping


def cmd_start(_args) -> int:
    """Start the broker if it is not already up."""
    _print(daemon.ensure_running())
    return 0


def cmd_stop(_args) -> int:
    """Stop a running broker."""
    print("stopped" if daemon.stop() else "not running")
    return 0


def cmd_status(_args) -> int:
    """Show broker health, or report that it is down."""
    health = daemon.probe()
    if not health:
        print(f"not running (would listen on {config.base_url()})")
        return 1
    _print(health)
    return 0


def cmd_request(args) -> int:
    """Ask the human for a secret through the browser form."""
    notify = {}
    if args.notify_command:
        notify["command"] = args.notify_command
    if args.notify_webhook:
        notify["webhook"] = args.notify_webhook
    result = Client().request_secret(
        name=args.name, purpose=args.purpose or "", target=args.target or "",
        hint=args.hint or "", requested_by=args.by, overwrite=args.overwrite,
        wait=args.wait, open_browser=not args.no_browser,
        notify=notify or None, preset=args.preset,
        fields=args.field or None)
    _print(result)
    return 0 if result.get("state") in ("fulfilled", "already_stored") else 1


def cmd_paste(args) -> int:
    """Type a secret straight into the store from this terminal."""
    value = getpass.getpass(f"value for {args.name} (hidden): ")
    if not value.strip():
        print("nothing entered", file=sys.stderr)
        return 1
    meta = store.put(args.name, value.strip(), purpose=args.purpose or "",
                     requested_by="local terminal")
    _print({k: meta[k] for k in ("name", "backend", "length", "fingerprint")})
    return 0


def cmd_wait(args) -> int:
    """Block until one request is answered, declined or expires."""
    result = Client().wait_for(args.request_id, args.seconds)
    _print(result)
    return 0 if result["state"] == "fulfilled" else 1


def cmd_events(args) -> int:
    """Print settled requests, optionally blocking for the next one."""
    _print(Client().events(since=args.since, wait=args.wait))
    return 0


def cmd_list(_args) -> int:
    """List stored secrets - names and metadata only."""
    _print(Client().list_secrets())
    return 0


def cmd_show(args) -> int:
    """Show metadata for one secret. Never prints the value."""
    _print(Client().describe(args.name))
    return 0


def cmd_rm(args) -> int:
    """Delete a stored secret."""
    _print(Client().delete(args.name))
    return 0


def cmd_run(args) -> int:
    """Run a command with secrets injected as environment variables."""
    result = Client().run(command=args.command, env=_env_pairs(args.env),
                          cwd=args.cwd or "", shell=args.shell,
                          timeout=args.timeout)
    if result["stdout"]:
        sys.stdout.write(result["stdout"])
    if result["stderr"]:
        sys.stderr.write(result["stderr"])
    return result["exit_code"] if result["exit_code"] is not None else 124


def cmd_write(args) -> int:
    """Render a template containing secrets into a private file."""
    template = args.template
    if args.template_file:
        template = open(args.template_file).read()
    if not template:
        raise SystemExit("pass --template or --template-file")
    _print(Client().materialize(path=args.path, template=template,
                                append=args.append))
    return 0


def cmd_mcp(_args) -> int:
    """Serve the MCP stdio protocol on this process."""
    from .mcp_server import serve_stdio
    serve_stdio()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Assemble the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sil", description="Secret input layer: agents ask, you paste.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("start", help="start the broker").set_defaults(fn=cmd_start)
    sub.add_parser("stop", help="stop the broker").set_defaults(fn=cmd_stop)
    sub.add_parser("status", help="broker health").set_defaults(fn=cmd_status)
    sub.add_parser("list", help="list stored secrets").set_defaults(fn=cmd_list)
    sub.add_parser("mcp", help="run the MCP stdio server").set_defaults(fn=cmd_mcp)

    ask = sub.add_parser("request", help="ask the human for a secret")
    ask.add_argument("name")
    ask.add_argument("--purpose", help="why the secret is needed")
    ask.add_argument("--target", help="where it will be used")
    ask.add_argument("--hint", help="label shown above the input box")
    ask.add_argument("--by", default="an agent", help="who is asking")
    ask.add_argument("--wait", type=float, default=config.DEFAULT_WAIT_SECONDS)
    ask.add_argument("--preset", choices=sorted(fields.PRESETS),
                     help="ask for a known credential shape")
    ask.add_argument("--field", action="append",
                     help="one field name; repeat for several")
    ask.add_argument("--overwrite", action="store_true")
    ask.add_argument("--no-browser", action="store_true")
    ask.add_argument("--notify-command", nargs=argparse.REMAINDER,
                     help="argv to run when the human answers (last flag)")
    ask.add_argument("--notify-webhook",
                     help="loopback http:// URL to POST the event to")
    ask.set_defaults(fn=cmd_request)

    hold = sub.add_parser("wait", help="block until a request is answered")
    hold.add_argument("request_id")
    hold.add_argument("--seconds", type=float,
                      default=config.DEFAULT_WAIT_SECONDS)
    hold.set_defaults(fn=cmd_wait)

    feed = sub.add_parser("events", help="settled requests, or wait for the next")
    feed.add_argument("--since", type=int, default=0)
    feed.add_argument("--wait", type=float, default=0)
    feed.set_defaults(fn=cmd_events)

    paste = sub.add_parser("paste", help="enter a secret from this terminal")
    paste.add_argument("name")
    paste.add_argument("--purpose")
    paste.set_defaults(fn=cmd_paste)

    show = sub.add_parser("show", help="metadata for one secret")
    show.add_argument("name")
    show.set_defaults(fn=cmd_show)

    remove = sub.add_parser("rm", help="delete a secret")
    remove.add_argument("name")
    remove.set_defaults(fn=cmd_rm)

    run = sub.add_parser("run", help="run a command with secrets in its env")
    run.add_argument("--env", action="append", metavar="VAR=secret")
    run.add_argument("--cwd")
    run.add_argument("--shell", action="store_true")
    run.add_argument("--timeout", type=float, default=config.RUN_TIMEOUT_SECONDS)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(fn=cmd_run)

    write = sub.add_parser("write", help="render secrets into a file")
    write.add_argument("path")
    write.add_argument("--template")
    write.add_argument("--template-file")
    write.add_argument("--append", action="store_true")
    write.set_defaults(fn=cmd_write)
    return parser


def main(argv=None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        return args.fn(args)
    except SilError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
