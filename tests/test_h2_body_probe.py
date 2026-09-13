"""Реальные h2-фреймы: HEAD нельзя принимать до завершения потока."""
import socketserver
import threading
import time
import unittest

from lucx_post_configurator.decoy_health import BrowserDialAddress, observe_decoy
from lucx_post_configurator.runner import Runner


class H2HeadBodyTests(unittest.TestCase):
    def test_head_waits_for_end_stream_and_rejects_late_data(self):
        self.check_head_body("public")

    def test_staging_head_waits_for_end_stream_and_rejects_late_data(self):
        self.check_head_body("staging")

    def check_head_body(self, phase):
        runner = Runner()
        if not runner.available("curl") or "HTTP2" not in runner.run(["curl", "--disable", "--version"]).stdout.split():
            self.skipTest("Нужен curl с HTTP2; сценарий обязателен на Linux-стенде")
        active_scenario = ["empty"]
        events = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                scenario = active_scenario[0]
                events.append((scenario, "accept"))
                def read(length):
                    data = b""
                    while len(data) < length:
                        chunk = self.request.recv(length - len(data))
                        if not chunk:
                            raise ConnectionError("Тестовый клиент закрыл поток")
                        data += chunk
                    return data
                def frame(kind, flags, stream, payload=b""):
                    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + stream + payload
                def literal(name, value):
                    return b"\x00" + bytes((len(name),)) + name + bytes((len(value),)) + value
                self.request.settimeout(2)
                try:
                    if read(24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
                        return
                    self.request.sendall(frame(4, 0, b"\x00" * 4))
                    for _ in range(16):
                        header = read(9)
                        read(int.from_bytes(header[:3], "big"))
                        if header[3] == 4 and not header[4] & 1:
                            self.request.sendall(frame(4, 1, b"\x00" * 4))
                        if header[3] != 1:
                            continue
                        events.append((scenario, "request"))
                        block = b"\x88" + literal(b"content-type", b"text/html")
                        block += literal(b"x-lucx-decoy", b"site.example.test")
                        block += literal(b"content-length", b"100")
                        self.request.sendall(frame(1, 5 if scenario == "empty" else 4, header[5:], block))
                        if scenario == "late_body":
                            time.sleep(0.05)
                            self.request.sendall(frame(0, 1, header[5:], b"illegal"))
                            events.append((scenario, "data_sent"))
                        # Не закрываем socket с непрочитанным SETTINGS ACK:
                        # Linux посылает RST при таком teardown. Ждём EOF клиента,
                        # а для unfinished — его timeout, сохраняя поток открытым.
                        for _ in range(64):
                            control = read(9)
                            payload = read(int.from_bytes(control[:3], "big"))
                            if control[3] == 4 and not control[4] & 1:
                                self.request.sendall(frame(4, 1, b"\x00" * 4))
                            elif control[3] == 6 and not control[4] & 1:
                                self.request.sendall(frame(6, 1, b"\x00" * 4, payload))
                        return
                except OSError as error:
                    events.append((scenario, type(error).__name__))
                    return

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                rows = []
                for scenario in ("empty", "late_body", "unfinished"):
                    active_scenario[0] = scenario
                    port = 8443 if phase == "staging" else server.server_address[1]
                    dial = BrowserDialAddress("127.0.0.1", server.server_address[1]) if phase == "staging" else None
                    rows.append(observe_decoy("site.example.test", "127.0.0.1", port,
                        "X-LucX-Decoy: site.example.test", method="HEAD", http_version="h2",
                        use_tls=False, strict_content=True, timeout=0.5, runner=runner,
                        phase=phase, dial_address=dial))
            finally:
                server.shutdown()
                thread.join(timeout=2)
        self.assertEqual(rows[0]["state"], "healthy", rows[0])
        self.assertTrue(rows[0]["body_absence_verified"])
        self.assertIn(("late_body", "data_sent"), events)
        self.assertIn(("unfinished", "request"), events)
        self.assertNotEqual(rows[1]["state"], "healthy", (rows[1], events))
        self.assertNotEqual(rows[2]["state"], "healthy", (rows[2], events))


if __name__ == "__main__":
    unittest.main()
