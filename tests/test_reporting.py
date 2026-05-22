import json
import os
import tempfile

from autonet.models.host import Host
from autonet.models.service import Service
from autonet.models.vulnerability import Vulnerability
from autonet.reporting.json_reporter import JSONReporter
from autonet.reporting.csv_reporter import CSVReporter


class TestJSONReporter:
    def test_report_empty(self):
        reporter = JSONReporter()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            reporter.report([], path)
            with open(path) as f:
                data = json.load(f)
            assert data["scan_metadata"]["hosts_scanned"] == 0
            assert data["hosts"] == []
        finally:
            os.unlink(path)

    def test_report_with_host(self, sample_host, sample_vulnerability):
        sample_host.services.append(
            Service(port=80, name="http", product="Apache", version="2.4.41")
        )
        sample_host.vulnerabilities.append(sample_vulnerability)

        reporter = JSONReporter()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            reporter.report([sample_host], path)
            with open(path) as f:
                data = json.load(f)
            assert data["scan_metadata"]["hosts_scanned"] == 1
            assert data["scan_metadata"]["total_vulnerabilities"] == 1
            assert data["hosts"][0]["ip"] == "192.168.1.10"
        finally:
            os.unlink(path)


class TestCSVReporter:
    def test_report_empty(self):
        reporter = CSVReporter()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            reporter.report([], path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 1  # header only
        finally:
            os.unlink(path)

    def test_report_with_host(self, sample_host, sample_vulnerability):
        sample_host.services.append(
            Service(port=443, name="https", product="Apache", version="2.4.41")
        )
        sample_host.vulnerabilities.append(sample_vulnerability)

        reporter = CSVReporter()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            reporter.report([sample_host], path)
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 2  # header + 1 data row
            assert "CVE-2021-41773" in lines[1]
        finally:
            os.unlink(path)
