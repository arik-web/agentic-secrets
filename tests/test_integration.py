"""HTTP and MCP integration tests against a live in-process daemon."""

import json
import os
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from support import cleanup, isolate

HOME = isolate()

from sil import auth, config, mcp_server, store  # noqa: E402
from sil.api import Api  # noqa: E402
from sil.client import Client  # noqa: E402
from sil.errors import SilError  # noqa: E402
from sil.server import SecretServer  # noqa: E402

SERVER = None
THREAD = None


def setUpModule():
    """Boot one daemon for the whole module."""
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


def raw(method: str, path: str, *, headers=None, data=None):
    """Perform an unauthenticated raw request and return (status, body)."""
    request = urllib.request.Request(f"{config.base_url()}{path}", data=data,
                                     method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read().decode()


def post_form(url: str, fields: dict):
    """Submit the paste form the way a browser would."""
    body = urllib.parse.urlencode(fields).encode()
    return raw("POST", url.replace(config.base_url(), ""), data=body,
               headers={"Content-Type": "application/x-www-form-urlencoded",
                        "Host": f"{config.HOST}:{config.port()}"})


class Guards(unittest.TestCase):
    """The daemon must refuse anything that is not a local, authorised call."""

    def test_api_needs_a_bearer_token(self):
        status, _ = raw("GET", "/api/secrets",
                        headers={"Host": f"{config.HOST}:{config.port()}"})
        self.assertEqual(status, 401)

    def test_api_rejects_a_wrong_token(self):
        status, _ = raw("GET", "/api/secrets", headers={
            "Host": f"{config.HOST}:{config.port()}",
            "Authorization": "Bearer not-the-token"})
        self.assertEqual(status, 401)

    def test_foreign_host_header_is_rejected(self):
        status, _ = raw("GET", "/healthz", headers={"Host": "evil.example"})
        self.assertEqual(status, 421)

    def test_health_is_open_and_value_free(self):
        status, body = raw("GET", "/healthz",
                           headers={"Host": f"{config.HOST}:{config.port()}"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_unknown_route_is_404(self):
        status, _ = raw("GET", "/api/nope", headers={
            "Host": f"{config.HOST}:{config.port()}",
            "Authorization": f"Bearer {auth.read_token()}"})
        self.assertEqual(status, 404)

    def test_token_file_is_owner_only(self):
        auth.read_token()
        mode = os.stat(config.TOKEN_FILE).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class PasteFlow(unittest.TestCase):
    """The whole point: an agent asks, a human pastes, the agent never sees it."""

    def setUp(self):
        self.client = Client(autostart=False)

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def _open_request(self, name="demo.key", **kwargs):
        """Create a non-blocking request and return its public view."""
        return self.client.request_secret(name=name, wait=0, purpose="testing",
                                          **kwargs)

    def test_request_response_contains_no_value_field(self):
        opened = self._open_request()
        self.assertEqual(opened["state"], "pending")
        self.assertNotIn("value", opened)

    def test_form_renders_the_context_the_human_needs(self):
        opened = self._open_request(target="/tmp/.env")
        status, page = raw("GET", opened["url"].replace(config.base_url(), ""),
                           headers={"Host": f"{config.HOST}:{config.port()}"})
        self.assertEqual(status, 200)
        self.assertIn("demo.key", page)
        self.assertIn("/tmp/.env", page)
        self.assertIn('type="password"', page)

    def test_paste_stores_the_value_and_settles_the_request(self):
        opened = self._open_request()
        status, page = post_form(opened["url"], {"action": "save",
                                                 "field.value": "sk-live-secret"})
        self.assertEqual(status, 200)
        self.assertIn("Saved", page)
        self.assertNotIn("sk-live-secret", page)
        self.assertEqual(
            self.client.request_status(opened["request_id"])["state"],
            "fulfilled")
        self.assertEqual(store.get("demo.key"), "sk-live-secret")

    def test_paste_link_cannot_be_replayed(self):
        opened = self._open_request()
        post_form(opened["url"], {"action": "save", "field.value": "first-value"})
        status, _ = post_form(opened["url"], {"action": "save",
                                             "field.value": "second-value"})
        self.assertEqual(status, 404)
        self.assertEqual(store.get("demo.key"), "first-value")

    def test_empty_paste_is_refused(self):
        opened = self._open_request()
        status, _ = post_form(opened["url"], {"action": "save", "field.value": "  "})
        self.assertEqual(status, 400)

    def test_human_can_decline(self):
        opened = self._open_request()
        post_form(opened["url"], {"action": "cancel"})
        self.assertEqual(
            self.client.request_status(opened["request_id"])["state"],
            "cancelled")

    def test_existing_secret_short_circuits_the_ask(self):
        store.put("demo.key", "already-here")
        self.assertEqual(self._open_request()["state"], "already_stored")

    def test_overwrite_forces_a_new_ask(self):
        store.put("demo.key", "already-here")
        self.assertEqual(self._open_request(overwrite=True)["state"], "pending")

    def test_agent_cancels_its_own_request(self):
        opened = self._open_request()
        self.assertEqual(
            self.client.cancel_request(opened["request_id"])["state"],
            "cancelled")


class Usage(unittest.TestCase):
    """Using a stored secret never returns it."""

    def setUp(self):
        self.client = Client(autostart=False)
        store.put("demo.key", "sk-live-usage")

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def test_list_and_describe_hide_the_value(self):
        listing = self.client.list_secrets()
        self.assertNotIn("sk-live-usage", json.dumps(listing))
        self.assertEqual(self.client.describe("demo.key")["length"], 13)

    def test_run_returns_scrubbed_output(self):
        result = self.client.run(command=["/bin/sh", "-c", "echo $K"],
                                 env={"K": "demo.key"})
        self.assertNotIn("sk-live-usage", result["stdout"])
        self.assertEqual(result["exit_code"], 0)

    def test_run_supports_shell_strings(self):
        result = self.client.run(command="test -n \"$K\" && echo present",
                                 env={"K": "demo.key"}, shell=True)
        self.assertIn("present", result["stdout"])

    def test_materialize_writes_the_file_but_returns_metadata_only(self):
        path = os.path.join(HOME, "written.env")
        result = self.client.materialize(path=path,
                                         template="K={{secret:demo.key}}\n")
        self.assertNotIn("sk-live-usage", json.dumps(result))
        with open(path) as handle:
            self.assertIn("sk-live-usage", handle.read())

    def test_materialize_mode_is_clamped_over_the_api(self):
        with self.assertRaises(SilError):
            self.client.materialize(path=os.path.join(HOME, "loose.env"),
                                    template="K={{secret:demo.key}}",
                                    mode="0o644")

    def test_materialize_rejects_a_malformed_mode_with_a_400(self):
        try:
            self.client.materialize(path=os.path.join(HOME, "bad.env"),
                                    template="K={{secret:demo.key}}",
                                    mode="not-octal")
            self.fail("expected a validation error")
        except SilError as exc:
            self.assertEqual(exc.status, 400)

    def test_wait_with_a_bad_number_is_a_400_not_a_500(self):
        opened = self.client.request_secret(name="wait.probe", wait=0)
        try:
            self.client.call("POST",
                             f"/api/request/{opened['request_id']}/wait",
                             {"wait": "soon"})
            self.fail("expected a validation error")
        except SilError as exc:
            self.assertEqual(exc.status, 400)

    def test_delete_removes_the_secret(self):
        self.client.delete("demo.key")
        self.assertFalse(store.exists("demo.key"))


class McpProtocol(unittest.TestCase):
    """The MCP layer must speak the protocol and never crash on bad input."""

    def call(self, method, params=None, mid=1):
        """Dispatch one JSON-RPC message through the server."""
        return mcp_server.handle({"jsonrpc": "2.0", "id": mid,
                                  "method": method, "params": params or {}})

    def test_initialize_advertises_tools(self):
        result = self.call("initialize")["result"]
        self.assertEqual(result["protocolVersion"], mcp_server.PROTOCOL_VERSION)
        self.assertIn("tools", result["capabilities"])

    def test_tools_list_is_complete_and_schema_shaped(self):
        tools = self.call("tools/list", mid=2)["result"]["tools"]
        self.assertIn("secret_request", [tool["name"] for tool in tools])
        for tool in tools:
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_every_tool_declares_its_read_only_hint(self):
        tools = self.call("tools/list", mid=3)["result"]["tools"]
        read_only = {tool["name"]: tool["annotations"]["readOnlyHint"]
                     for tool in tools}
        self.assertTrue(all(read_only[name] for name in
                            ["secret_list", "secret_describe", "secret_health",
                             "secret_status", "secret_wait", "secret_events"]))
        self.assertFalse(any(read_only[name] for name in
                             ["secret_request", "secret_run",
                              "secret_write_file", "secret_delete"]))

    def test_notifications_get_no_response(self):
        self.assertIsNone(mcp_server.handle(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_unknown_method_is_a_jsonrpc_error(self):
        self.assertEqual(self.call("nope")["error"]["code"],
                         mcp_server.METHOD_NOT_FOUND)

    def test_unknown_tool_is_a_tool_error_not_a_crash(self):
        result = self.call("tools/call", {"name": "nope", "arguments": {}})
        self.assertTrue(result["result"]["isError"])

    def test_tool_error_is_reported_without_a_traceback(self):
        result = self.call("tools/call",
                           {"name": "secret_describe",
                            "arguments": {"name": "not-stored"}})["result"]
        self.assertTrue(result["isError"])
        self.assertNotIn("Traceback", json.dumps(result))

    def test_health_tool_round_trips(self):
        result = self.call("tools/call",
                           {"name": "secret_health", "arguments": {}})["result"]
        self.assertFalse(result["isError"])
        self.assertTrue(result["structuredContent"]["ok"])


if __name__ == "__main__":
    unittest.main()


class MultiField(unittest.TestCase):
    """One window, several boxes, one secret stored per box."""

    def setUp(self):
        self.client = Client(autostart=False)

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def _open(self, **kwargs):
        """Open a non-blocking request and return its public view."""
        return self.client.request_secret(wait=0, **kwargs)

    def test_a_preset_expands_into_named_fields(self):
        opened = self._open(name="kraken", preset="api_key_secret")
        self.assertEqual([f["secret_name"] for f in opened["fields"]],
                         ["kraken.api_key", "kraken.api_secret"])

    def test_the_form_shows_every_field_with_its_label(self):
        opened = self._open(name="broker", preset="username_password")
        _, page = raw("GET", opened["url"].replace(config.base_url(), ""),
                      headers={"Host": f"{config.HOST}:{config.port()}"})
        self.assertIn("Username", page)
        self.assertIn("Password", page)
        self.assertIn("broker.password", page)
        self.assertIn('name="field.username"', page)

    def test_a_username_field_is_not_masked(self):
        opened = self._open(name="broker", preset="username_password")
        _, page = raw("GET", opened["url"].replace(config.base_url(), ""),
                      headers={"Host": f"{config.HOST}:{config.port()}"})
        self.assertIn('name="field.username" type="text"', page)
        self.assertIn('name="field.password" type="password"', page)

    def test_saving_stores_one_secret_per_field(self):
        opened = self._open(name="kraken", preset="api_key_secret")
        status, page = post_form(opened["url"], {
            "action": "save", "field.api_key": "KEY-aaaa",
            "field.api_secret": "SECRET-bbbb"})
        self.assertEqual(status, 200)
        self.assertIn("kraken.api_key", page)
        self.assertEqual(store.get("kraken.api_key"), "KEY-aaaa")
        self.assertEqual(store.get("kraken.api_secret"), "SECRET-bbbb")

    def test_the_settled_request_lists_what_it_stored(self):
        opened = self._open(name="kraken", preset="api_key_secret")
        post_form(opened["url"], {"action": "save", "field.api_key": "KEY-aaaa",
                                  "field.api_secret": "SECRET-bbbb"})
        settled = self.client.request_status(opened["request_id"])
        self.assertEqual(settled["state"], "fulfilled")
        self.assertEqual(settled["stored"],
                         ["kraken.api_key", "kraken.api_secret"])

    def test_a_missing_required_field_names_what_is_missing(self):
        opened = self._open(name="kraken", preset="api_key_secret")
        status, page = post_form(opened["url"], {
            "action": "save", "field.api_key": "KEY-aaaa"})
        self.assertEqual(status, 400)
        self.assertIn("API secret", page)
        self.assertFalse(store.exists("kraken.api_key"))

    def test_an_optional_field_may_be_left_blank(self):
        opened = self._open(name="bank", preset="basic_auth_totp")
        status, _ = post_form(opened["url"], {
            "action": "save", "field.username": "arik",
            "field.password": "hunter2222", "field.totp_seed": ""})
        self.assertEqual(status, 200)
        self.assertFalse(store.exists("bank.totp_seed"))
        self.assertTrue(store.exists("bank.password"))

    def test_custom_fields_are_accepted_as_bare_names(self):
        opened = self._open(name="pg", fields=["host", "password"])
        self.assertEqual([f["secret_name"] for f in opened["fields"]],
                         ["pg.host", "pg.password"])

    def test_fields_and_preset_together_are_refused(self):
        with self.assertRaises(SilError):
            self._open(name="pg", fields=["host"], preset="token")

    def test_an_unknown_preset_is_refused(self):
        with self.assertRaises(SilError):
            self._open(name="pg", preset="nope")

    def test_a_single_field_request_still_stores_under_the_bare_name(self):
        opened = self._open(name="github.pat")
        post_form(opened["url"], {"action": "save",
                                  "field.value": "ghp-token-value"})
        self.assertEqual(store.get("github.pat"), "ghp-token-value")

    def test_already_stored_only_when_every_field_is_held(self):
        store.put("kraken.api_key", "KEY-aaaa")
        partial = self._open(name="kraken", preset="api_key_secret")
        self.assertEqual(partial["state"], "pending")
        store.put("kraken.api_secret", "SECRET-bbbb")
        self.assertEqual(self._open(name="kraken",
                                    preset="api_key_secret")["state"],
                         "already_stored")

    def test_each_field_is_usable_on_its_own(self):
        opened = self._open(name="kraken", preset="api_key_secret")
        post_form(opened["url"], {"action": "save", "field.api_key": "KEY-aaaa",
                                  "field.api_secret": "SECRET-bbbb"})
        result = self.client.run(
            command=["/bin/sh", "-c", "echo $K; echo $S"],
            env={"K": "kraken.api_key", "S": "kraken.api_secret"})
        self.assertNotIn("KEY-aaaa", result["stdout"])
        self.assertNotIn("SECRET-bbbb", result["stdout"])
        self.assertEqual(sorted(result["scrubbed"]),
                         ["kraken.api_key", "kraken.api_secret"])
