"""VirusTotal integration tests. All provider requests use mocks; no real key or uploads."""
import base64
import hashlib
import io
import json
import os
import unittest
from unittest.mock import patch
import urllib.error

from backend import virustotal as vt, web


class VTTests(unittest.TestCase):
    def response(self, obj):
        return io.BytesIO(json.dumps(obj).encode("utf-8"))

    def test_lookup_returns_real_counts_and_source_link(self):
        data = {"data":{"attributes":{"sha256":"a"*64,"last_analysis_date":1730000000,
                "last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":36,"undetected":22}}}}
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request, "urlopen", return_value=self.response(data)) as send:
                result=vt.hash_report({"hash":"A"*64})
        self.assertEqual(result["status"],"found")
        self.assertEqual(result["stats"]["malicious"],2)
        self.assertEqual(result["stats"]["undetected"],22)
        self.assertTrue(result["reportUrl"].endswith("/file/"+("a"*64)+"/detection"))
        self.assertEqual(send.call_args.args[0].get_method(),"GET")
        self.assertNotIn("test-only",str(result))

    def test_missing_hash_is_not_a_clean_verdict(self):
        error=urllib.error.HTTPError("https://www.virustotal.com/api/v3/files/abc",404,"Not Found",{},io.BytesIO(b""))
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request,"urlopen",side_effect=error):
                result=vt.hash_report({"hash":"b"*64})
        self.assertEqual(result["status"],"not_found")
        self.assertNotIn("safe",json.dumps(result).lower())
        self.assertIn("NOT",result["message"])

    def test_no_key_does_not_claim_scan(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY":""}):
            with self.assertRaises(vt.VTError) as caught:vt.hash_report({"hash":"c"*64})
        self.assertEqual(caught.exception.status,503)

    def test_file_requires_consent_and_enforces_size(self):
        with patch.object(vt.urllib.request,"urlopen",side_effect=AssertionError("must not upload")):
            with self.assertRaises(vt.VTError):vt.submit_file({"filename":"a.pdf","data":base64.b64encode(b"small").decode()})
            with self.assertRaises(vt.VTError):vt.submit_file({"filename":"a.pdf","data":"a"*(vt.MAX_FILE_BYTES*4//3+9),"consent":True})
            with self.assertRaises(vt.VTError):vt.submit_file({"filename":"a.pdf","data":base64.b64encode(b"x").decode(),"sha256":"f"*64,"consent":True})

    def test_file_upload_has_multipart_body_only_when_consented(self):
        content=b"%PDF-example-disposable-test-document"
        posted={"data":{"id":"ZmlsZS1hbmFseXNpcy1pZA=="}}
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY":"private-test-only"}):
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response(posted)) as send:
                result=vt.submit_file({"filename":"sample.pdf","data":base64.b64encode(content).decode(),
                                      "sha256":hashlib.sha256(content).hexdigest(),"consent":True})
        self.assertEqual(result["status"],"queued")
        self.assertEqual(result["sha256"],hashlib.sha256(content).hexdigest())
        req=send.call_args.args[0]
        self.assertEqual(req.get_method(),"POST")
        self.assertIn("multipart/form-data",req.get_header("Content-type"))
        self.assertIn(content,req.data)
        self.assertEqual(result["analysisId"],"ZmlsZS1hbmFseXNpcy1pZA==")
        self.assertNotIn("private-test-only",str(result))

    def test_public_url_lookup_never_visits_site(self):
        doc={"data":{"id":"a"*64,"attributes":{"last_analysis_stats":{"malicious":0,"harmless":60}}}}
        with patch.dict(os.environ,{"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response(doc)) as send:
                result=vt.url_report({"url":"https://example.com/path#private-fragment"})
        self.assertEqual(result["status"],"found")
        req=send.call_args.args[0]
        self.assertTrue(req.full_url.startswith("https://www.virustotal.com/api/v3/urls/"))
        self.assertNotIn("private-fragment",req.full_url)
        self.assertEqual(req.get_method(),"GET")
        self.assertEqual(result["stats"]["harmless"],60)

    def test_url_submit_requires_consent_and_blocks_local(self):
        for bad in ("http://localhost:8888/","http://127.0.0.1","http://192.168.1.50/","http://metadata.local/","file:///etc/passwd","http://user:pass@example.com"):
            with self.subTest(bad=bad),self.assertRaises(vt.VTError):vt.submit_url({"url":bad,"consent":True})
        with self.assertRaises(vt.VTError):vt.submit_url({"url":"https://example.com","consent":False})
        with patch.dict(os.environ,{"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response({"data":{"id":"u-test-analysis-123"}})) as send:
                result=vt.submit_url({"url":"https://example.com/","consent":True})
        self.assertEqual(result["status"],"queued")
        self.assertEqual(send.call_args.args[0].get_method(),"POST")
        self.assertIn(b"url=https%3A%2F%2Fexample.com%2F",send.call_args.args[0].data)

    def test_analysis_queue_then_completed(self):
        with patch.dict(os.environ,{"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response({"data":{"attributes":{"status":"queued"}}})):
                waiting=vt.analysis({"analysisId":"analysis-test-12345"})
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response({"data":{"attributes":{"status":"completed","stats":{"malicious":1,"suspicious":0,"harmless":15,"undetected":8}}}})):
                done=vt.analysis({"analysisId":"analysis-test-12345"})
        self.assertEqual(waiting["status"],"queued")
        self.assertEqual(done["status"],"completed")
        self.assertEqual(done["stats"]["malicious"],1)

    def test_rate_limits_use_explicit_message(self):
        error=urllib.error.HTTPError("https://www.virustotal.com",429,"rate limit",{},io.BytesIO(b""))
        with patch.dict(os.environ,{"VIRUSTOTAL_API_KEY":"test-only"}):
            with patch.object(vt.urllib.request,"urlopen",side_effect=error):
                with self.assertRaises(vt.VTError) as caught:vt.hash_report({"hash":"a"*64})
        self.assertEqual(caught.exception.status,429)
        self.assertIn("rate limit",str(caught.exception).lower())

    def test_cloud_route_requires_login_and_does_not_bootstrap_db(self):
        client=web.app.test_client()
        with patch.dict(os.environ,{"APP_USERNAME":"admin","APP_PASSWORD":"really-long-test-password",
                                     "MONGODB_URI":"","VIRUSTOTAL_API_KEY":"test-only"}):
            self.assertEqual(client.post("/api/vt/hash",json={"hash":"d"*64}).status_code,401)
            header={"Authorization":"Basic "+base64.b64encode(b"admin:really-long-test-password").decode()}
            with patch.object(vt.urllib.request,"urlopen",return_value=self.response({
                "data":{"attributes":{"sha256":"d"*64,"last_analysis_stats":{"harmless":1}}}
            })):
                answer=client.post("/api/vt/hash",json={"hash":"d"*64},headers=header)
            self.assertEqual(answer.status_code,200)
            self.assertEqual(answer.get_json()["stats"]["harmless"],1)
            self.assertEqual(client.get("/api/vt/hash",headers=header).status_code,405)


if __name__=="__main__":
    unittest.main()
