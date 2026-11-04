import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from netsensor.ingest import IngestError, check_target, forward, live_forwarder, heartbeat_sender

# Shape of a real alert payload (see netsensor/ml/alerts.py); values are a test fixture.
PAYLOAD = {
    "organizationId": "000000000000000000000000", "endpointId": "000000000000000000000000",
    "attackType": "DOS_DDOS", "ruleId": "DOS-XGB", "riskScore": 73, "confidenceTier": "suspicious",
    "modelVersion": "dos-xgb-test", "detectorStatus": "TRAINED", "dataOrigin": "PCAP_REPLAY",
    "detectedAt": "2018-11-03T14:29:20Z", "indicators": [{"type": "NETWORK_FLOOD", "description": "x"}],
    "evidence": [{"id": "dos-window", "source": "netsensor", "time": "2018-11-03T14:29:20Z",
                  "description": "w", "fields": {"target": "192.168.50.4"}}],
}


class _Capture(BaseHTTPRequestHandler):
    received = []
    status = 201

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Capture.received.append({"path": self.path, "key": self.headers.get("x-api-key"), "body": body})
        if _Capture.status == 201:
            reply = {"detection": {"_id": f"det{len(_Capture.received)}"}}
        elif _Capture.status == 200:
            reply = {"duplicate": True, "detection": {"_id": "existing1"}}
        else:
            reply = {"message": "bad"}
        data = json.dumps(reply).encode()
        self.send_response(_Capture.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        _Capture.received, _Capture.status = [], 201
        self.server = HTTPServer(("127.0.0.1", 0), _Capture)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.server.server_port}/api"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp)

    def alerts(self, *payloads):
        path = os.path.join(self.tmp, "alerts.jsonl")
        with open(path, "w", encoding="utf-8") as stream:
            for p in payloads:
                stream.write(json.dumps(p) + "\n")
        return path

    def test_posts_each_alert_with_ids_and_key_and_logs_results(self):
        path = self.alerts(PAYLOAD, dict(PAYLOAD, detectedAt="2018-11-03T14:30:00Z", _fixture="note"))
        result = forward(path, self.api, "org1", "ep1", "secret-key")
        self.assertEqual((result["alerts"], result["created"], result["failed"]), (2, 2, 0))
        self.assertEqual([r["path"] for r in _Capture.received], ["/api/detections/ingest"] * 2)
        self.assertTrue(all(r["key"] == "secret-key" for r in _Capture.received))
        body = _Capture.received[1]["body"]
        self.assertEqual((body["organizationId"], body["endpointId"]), ("org1", "ep1"))
        self.assertNotIn("_fixture", body)
        self.assertEqual(body["dataOrigin"], "PCAP_REPLAY")
        with open(result["log"], encoding="utf-8") as stream:
            log = [json.loads(l) for l in stream]
        self.assertEqual([l["detection_id"] for l in log], ["det1", "det2"])
        self.assertNotIn("secret-key", open(result["log"], encoding="utf-8").read())

    def test_refuses_to_resend_and_reports_server_rejections(self):
        path = self.alerts(PAYLOAD)
        forward(path, self.api, "o", "e", "k")
        with self.assertRaisesRegex(IngestError, "already forwarded"):
            forward(path, self.api, "o", "e", "k")
        os.remove(os.path.join(self.tmp, "ingest-log.jsonl"))
        _Capture.status = 400
        result = forward(path, self.api, "o", "e", "k")
        self.assertEqual((result["created"], result["failed"]), (0, 1))

    def test_replays_to_a_fresh_log_and_counts_server_side_duplicates(self):
        path = self.alerts(PAYLOAD)
        first = forward(path, self.api, "o", "e", "k", log_path=os.path.join(self.tmp, "run1", "log.jsonl"))
        self.assertEqual((first["created"], first["already_recorded"], first["failed"]), (1, 0, 0))
        _Capture.status = 200      # the backend already holds this alert episode
        second = forward(path, self.api, "o", "e", "k", log_path=os.path.join(self.tmp, "run2.jsonl"))
        self.assertEqual((second["created"], second["already_recorded"], second["failed"]), (0, 1, 0))
        self.assertEqual(second["detection_ids"], ["existing1"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ingest-log.jsonl")), "nothing written next to the alerts")
        with self.assertRaisesRegex(IngestError, "already forwarded"):
            forward(path, self.api, "o", "e", "k", log_path=os.path.join(self.tmp, "run2.jsonl"))

    def test_guards(self):
        with self.assertRaisesRegex(IngestError, "non-local"):
            check_target("https://backend.example.com/api", allow_remote=False)
        self.assertTrue(check_target("https://backend.example.com/api", allow_remote=True).endswith("/detections/ingest"))
        for bad, why in ((dict(PAYLOAD, detectorStatus="SYNTHETIC_TEST_ONLY"), "TRAINED or HEURISTIC"),
                         (dict(PAYLOAD, attackType="RANSOMWARE"), "not DOS_DDOS"),
                         ({k: v for k, v in PAYLOAD.items() if k != "dataOrigin"}, "dataOrigin")):
            with self.subTest(why):
                with self.assertRaisesRegex(IngestError, why):
                    forward(self.alerts(bad), self.api, "o", "e", "k")
        self.assertEqual(_Capture.received, [])   # nothing was sent for invalid input
        with self.assertRaisesRegex(IngestError, "no API key"):
            forward(self.alerts(PAYLOAD), self.api, "o", "e", None)

    def test_dry_run_sends_nothing(self):
        result = forward(self.alerts(PAYLOAD), self.api, "o", "e", None, dry_run=True)
        self.assertEqual((result["alerts"], result["dry_run"]), (1, True))
        self.assertEqual(_Capture.received, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ingest-log.jsonl")))


    def test_live_forwarder_posts_and_returns_detection_id(self):
        send = live_forwarder(self.api, "orgL", "epL", "secret-key")
        det_id = send(dict(PAYLOAD))
        self.assertEqual(det_id, "det1")
        body = _Capture.received[-1]["body"]
        self.assertEqual((body["organizationId"], body["endpointId"]), ("orgL", "epL"))
        self.assertEqual(body["dataOrigin"], "PCAP_REPLAY")
        # LIVE payloads are accepted too.
        send(dict(PAYLOAD, dataOrigin="LIVE"))
        self.assertEqual(_Capture.received[-1]["body"]["dataOrigin"], "LIVE")

    def test_live_forwarder_rejects_invalid_payload_and_remote(self):
        send = live_forwarder(self.api, "o", "e", "k")
        with self.assertRaisesRegex(IngestError, "not DOS_DDOS"):
            send(dict(PAYLOAD, attackType="RANSOMWARE"))
        with self.assertRaisesRegex(IngestError, "non-local"):
            live_forwarder("https://backend.example.com/api", "o", "e", "k")

    def test_live_forwarder_raises_on_backend_error(self):
        _Capture.status = 500
        send = live_forwarder(self.api, "o", "e", "k")
        with self.assertRaisesRegex(IngestError, "HTTP 500"):
            send(dict(PAYLOAD))

    def test_heartbeat_sender_hits_endpoint_heartbeat(self):
        _Capture.status = 200  # the real /heartbeat endpoint returns 200
        beat = heartbeat_sender(self.api, "ep9", "secret-key")
        self.assertTrue(beat())
        self.assertEqual(_Capture.received[-1]["path"], "/api/endpoints/ep9/heartbeat")

if __name__ == "__main__":
    unittest.main()
