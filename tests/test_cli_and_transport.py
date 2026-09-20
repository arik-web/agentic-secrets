"""CLI, stdio transport, browser launch and daemon-probe coverage."""

import io
import json
import os
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from support import cleanup, isolate, python_command

HOME = isolate()

from sil import browser, cli, daemon, mcp_server, store  # noqa: E402
from sil.api import Api  # noqa: E402
from sil.server import SecretServer  # noqa: E402

SERVER = None
THREAD = None


def setUpModule():
    """Boot one daemon so the CLI's autostart probe finds it already up."""
    global SERVER, THREAD
    SERVER = SecretServer(Api())
    THREAD = threading.Thread(target=SERVER.serve_forever, daemon=True)
    THREAD.start()


def tearDownModule():
    """Stop the daemon and drop the throwaway home."""
    SERVER.shutdown()
    SERVER.server_close()
    THREAD.join(timeout=5)
    cleanup(HOME)


def run_cli(argv):
    """Run the CLI and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class DaemonProbe(unittest.TestCase):
    """`probe` and `is_running` are what every other entry point trusts."""

    def test_probe_sees_the_running_daemon(self):
        self.assertTrue(daemon.is_running())
        self.assertTrue(daemon.probe()["ok"])

    def test_ensure_running_is_a_no_op_when_up(self):
        self.assertTrue(daemon.ensure_running()["ok"])


class BrowserLaunch(unittest.TestCase):
    """The paste window has to actually be opened for the human."""

    def test_custom_browser_override_is_used(self):
        self.assertEqual(browser.open_url("http://127.0.0.1:1/x"),
                         "custom:" + os.environ["SIL_BROWSER"])


class Cli(unittest.TestCase):
    """The CLI is the fallback surface for agents without MCP."""

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def test_status_prints_health(self):
        code, out, _ = run_cli(["status"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["ok"])

    def test_list_is_empty_at_first(self):
        code, out, _ = run_cli(["list"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["secrets"], [])

    def test_paste_stores_from_the_terminal(self):
        original = cli.getpass.getpass
        cli.getpass.getpass = lambda prompt="": "typed-secret"
        try:
            code, out, _ = run_cli(["paste", "cli.key", "--purpose", "testing"])
        finally:
            cli.getpass.getpass = original
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["length"], 12)
        self.assertEqual(store.get("cli.key"), "typed-secret")

    def test_paste_refuses_an_empty_entry(self):
        original = cli.getpass.getpass
        cli.getpass.getpass = lambda prompt="": "   "
        try:
            code, _, err = run_cli(["paste", "cli.key"])
        finally:
            cli.getpass.getpass = original
        self.assertEqual(code, 1)
        self.assertIn("nothing entered", err)

    def test_show_reports_metadata_without_the_value(self):
        store.put("cli.key", "sk-cli-value")
        code, out, _ = run_cli(["show", "cli.key"])
        self.assertEqual(code, 0)
        self.assertNotIn("sk-cli-value", out)

    def test_run_injects_and_scrubs(self):
        store.put("cli.key", "sk-cli-value")
        code, out, _ = run_cli(["run", "--env", "K=cli.key", "--",
                                *python_command(
                                    'import os; print(os.environ["K"])')])
        self.assertEqual(code, 0)
        self.assertNotIn("sk-cli-value", out)

    def test_run_rejects_a_malformed_env_pair(self):
        with self.assertRaises(SystemExit):
            run_cli(["run", "--env", "NOEQUALS", "--",
                     *python_command("pass")])

    def test_write_renders_a_template_file(self):
        store.put("cli.key", "sk-cli-value")
        path = f"{HOME}/cli.env"
        code, out, _ = run_cli(["write", path, "--template",
                                "K={{secret:cli.key}}\n"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["secrets_used"], ["cli.key"])

    def test_write_without_a_template_exits(self):
        with self.assertRaises(SystemExit):
            run_cli(["write", f"{HOME}/x.env"])

    def test_rm_deletes(self):
        store.put("cli.key", "value")
        self.assertEqual(run_cli(["rm", "cli.key"])[0], 0)
        self.assertFalse(store.exists("cli.key"))

    def test_request_reports_already_stored(self):
        store.put("cli.key", "value")
        code, out, _ = run_cli(["request", "cli.key", "--wait", "0"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "already_stored")

    def test_error_from_the_broker_becomes_exit_two(self):
        code, _, err = run_cli(["show", "missing.key"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)


class StdioTransport(unittest.TestCase):
    """`sil mcp` speaks newline-delimited JSON-RPC on stdin/stdout."""

    def drive(self, lines):
        """Feed lines through serve_stdio and return the decoded replies."""
        sink = io.StringIO()
        mcp_server.serve_stdio(io.StringIO("\n".join(lines) + "\n"), sink)
        return [json.loads(line) for line in sink.getvalue().splitlines()]

    def test_handshake_then_tool_call(self):
        replies = self.drive([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "secret_health"}}),
        ])
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]["result"]["serverInfo"]["name"],
                         "secret-input-layer")
        self.assertTrue(replies[1]["result"]["structuredContent"]["ok"])

    def test_blank_lines_are_ignored(self):
        self.assertEqual(self.drive(["", "  ", json.dumps(
            {"jsonrpc": "2.0", "id": 9, "method": "ping"})])[0]["id"], 9)

    def test_malformed_json_gets_a_parse_error_and_the_loop_survives(self):
        replies = self.drive(["{not json", json.dumps(
            {"jsonrpc": "2.0", "id": 3, "method": "ping"})])
        self.assertEqual(replies[0]["error"]["code"], mcp_server.PARSE_ERROR)
        self.assertEqual(replies[1]["id"], 3)

    def test_tools_call_without_a_name_is_invalid_params(self):
        replies = self.drive([json.dumps(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}})])
        self.assertEqual(replies[0]["error"]["code"], mcp_server.INVALID_PARAMS)


if __name__ == "__main__":
    unittest.main()
