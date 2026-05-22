import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from autonet.models.host import Host
from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability
from autonet.vuln_matching.cve_lookup import CVELookupMatcher


class TestCVELookupMatcher:
    def test_parse_vulners_response(self):
        data = {
            "data": {
                "search": [
                    {
                        "_source": {
                            "id": "CVE-2021-41773",
                            "cvss": {"severity": "HIGH", "score": 7.5},
                            "description": "Path traversal vulnerability",
                        }
                    }
                ]
            }
        }
        vulns = CVELookupMatcher._parse_vulners_response(data, "Apache httpd", "2.4.41")
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2021-41773"
        assert vulns[0].severity == "HIGH"

    def test_parse_ignores_non_cve(self):
        data = {
            "data": {
                "search": [
                    {"_source": {"id": "BUG-12345", "cvss": {}, "description": ""}}
                ]
            }
        }
        vulns = CVELookupMatcher._parse_vulners_response(data, "nginx", "1.18")
        assert len(vulns) == 0

    def test_parse_empty_response(self):
        vulns = CVELookupMatcher._parse_vulners_response({}, "test", "1.0")
        assert vulns == []

    def test_no_product_or_version(self):
        matcher = CVELookupMatcher()
        host = Host(ip="10.0.0.1", is_alive=True)
        host.services.append(Service(port=80, name="http"))
        result = asyncio.run(matcher.match([host]))
        assert len(result[0].vulnerabilities) == 0
