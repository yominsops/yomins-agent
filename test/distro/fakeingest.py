#!/usr/bin/env python3
"""Fake ingest server for test/distro: stores what each agent posts.

    fakeingest.py <dir> <port>

metrics keeps the last push, events and logs everything, in <dir>/<token>/.
"""
import gzip, http.server, os, sys

OUT, PORT = sys.argv[1], int(sys.argv[2])


class H(http.server.BaseHTTPRequestHandler):
    def _tok(self):
        return self.headers.get("Authorization", "none").split()[-1].replace("/", "_")

    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        kind = self.path.rstrip("/").split("/")[-1]
        d = os.path.join(OUT, self._tok())
        os.makedirs(d, exist_ok=True)
        mode = "wb" if kind == "metrics" else "ab"  # metrics: keep the last push
        with open(os.path.join(d, kind), mode) as f:
            f.write(body if body.endswith(b"\n") else body + b"\n")
        self.send_response(204)
        self.send_header("X-Yomins-Accept-Encoding", "gzip")
        self.end_headers()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
