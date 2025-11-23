"""
Unit tests for detection_agent_service FastAPI backend.

Tests all endpoints and critical behavior using pytest fixtures, FastAPI's TestClient,
and mocked external effects to ensure test hermiticity.
"""

import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from agent_service.detection_agent_service import (
    LEGACY_RESULTS_DIR_ENV_VAR,
    RESULTS_DIR_ENV_VAR,
    app,
    get_results_directory,
    read_payload_json,
    write_payload_json,
)
from agent_service.log_parser import LogEntry


@pytest.fixture
def tmp_results_dir(tmp_path, monkeypatch):
    """Fixture to set STATIC_RESULTS_DIR to a temporary directory."""
    results_dir = tmp_path / "agent_results"
    results_dir.mkdir(exist_ok=True)
    monkeypatch.setenv(RESULTS_DIR_ENV_VAR, str(results_dir))
    return results_dir


@pytest.fixture
def client(tmp_results_dir):
    """Fixture to provide a TestClient instance."""
    return TestClient(app)


@pytest.fixture
def mock_collect_logs(monkeypatch):
    """Fixture to mock collect_logs with deterministic log summaries."""
    def _mock_collect_logs(start_time, end_time, log_sources=None):
        """
        Mock implementation that returns deterministic log summaries.
        
        Args:
            start_time: Start time for log collection
            end_time: End time for log collection
            log_sources: List of log source types to collect
            
        Returns:
            Dictionary with log summaries keyed by log type
        """
        results = {}
        
        # Default log sources if not specified
        if log_sources is None:
            log_sources = ['audit', 'syslog', 'auth', 'yum']
        
        # Create deterministic log entries for each source
        for source in log_sources:
            entries = []
            
            # Create sample log entries
            for i in range(2):
                log_time = start_time + timedelta(seconds=i)
                entry = LogEntry(
                    timestamp=log_time,
                    source=f'/var/log/{source}.log',
                    host='localhost',
                    process=f'process_{source}_{i}',
                    pid=1000 + i,
                    message=f'Test {source} message {i}',
                    raw_line=f'Raw line for {source} {i}',
                    metadata={'test': 'true', 'index': str(i)}
                )
                entries.append(entry)
            
            results[source] = {
                'count': len(entries),
                'entries': entries,
                'path': f'/var/log/{source}.log'
            }
        
        return results
    
    monkeypatch.setattr(
        'agent_service.detection_agent_service.collect_logs',
        _mock_collect_logs
    )
    return _mock_collect_logs


@pytest.fixture
def mock_subprocess_success(monkeypatch):
    """Fixture to mock subprocess.run for successful execution."""
    def _run_mock(command, **kwargs):
        mock_result = Mock()
        mock_result.stdout = f"Output from: {command}"
        mock_result.stderr = ""
        mock_result.returncode = 0
        return mock_result
    
    monkeypatch.setattr('subprocess.run', _run_mock)
    return _run_mock


@pytest.fixture
def mock_subprocess_failure(monkeypatch):
    """Fixture to mock subprocess.run for failed execution."""
    def _run_mock(command, **kwargs):
        mock_result = Mock()
        mock_result.stdout = ""
        mock_result.stderr = f"Error: command failed"
        mock_result.returncode = 1
        return mock_result
    
    monkeypatch.setattr('subprocess.run', _run_mock)
    return _run_mock


@pytest.fixture
def mock_subprocess_timeout(monkeypatch):
    """Fixture to mock subprocess.run to raise TimeoutExpired."""
    def _run_mock(command, **kwargs):
        timeout = kwargs.get('timeout', 30)
        exc = subprocess.TimeoutExpired(command, timeout)
        exc.stdout = "partial"
        exc.stderr = ""
        raise exc
    
    monkeypatch.setattr('subprocess.run', _run_mock)
    return _run_mock


class TestGetAgents:
    """Test cases for GET /api/agents endpoint."""
    
    def test_get_agents_returns_localhost(self, client):
        """Test that GET /api/agents returns the localhost agent."""
        response = client.get("/api/agents")
        
        assert response.status_code == 200
        agents = response.json()
        
        assert len(agents) > 0
        localhost_agent = agents[0]
        assert localhost_agent["agent_id"] == "localhost"
        assert localhost_agent["hostname"] == "localhost"
        assert localhost_agent["status"] == "online"
        assert localhost_agent["ip_address"] == "127.0.0.1"
    
    def test_get_agents_includes_last_seen(self, client):
        """Test that agents include last_seen timestamp."""
        response = client.get("/api/agents")
        
        assert response.status_code == 200
        agents = response.json()
        
        assert len(agents) > 0
        agent = agents[0]
        assert "last_seen" in agent
        # Verify it's a valid ISO format timestamp
        assert isinstance(agent["last_seen"], str)
        datetime.fromisoformat(agent["last_seen"])


class TestExecutePayload:
    """Test cases for POST /api/payloads endpoint."""
    
    def test_execute_payload_success(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test successful payload execution."""
        request_data = {
            "command": "echo hello",
            "description": "Simple echo command"
        }
        
        response = client.post("/api/payloads", json=request_data)
        
        assert response.status_code == 200
        payload = response.json()
        
        assert "payload_id" in payload
        assert payload["command"] == "echo hello"
        assert payload["description"] == "Simple echo command"
        assert payload["status"] == "completed"
        assert payload["return_code"] == 0
        assert "duration" in payload
        assert payload["duration"] > 0
        assert "stdout" in payload
        assert "stderr" in payload
        assert "logs" in payload
        assert payload["storage_path"].endswith(".json")
    
    def test_execute_payload_with_failed_command(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_failure):
        """Test payload execution with command failure."""
        request_data = {
            "command": "false",
            "description": "Command that fails"
        }
        
        response = client.post("/api/payloads", json=request_data)
        
        assert response.status_code == 200
        payload = response.json()
        
        assert payload["status"] == "failed"
        assert payload["return_code"] == 1
    
    def test_execute_payload_with_timeout(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_timeout):
        """Test payload execution with timeout."""
        request_data = {
            "command": "sleep 1000",
            "description": "Command that times out"
        }
        
        response = client.post("/api/payloads", json=request_data)
        
        assert response.status_code == 200
        payload = response.json()
        
        assert payload["status"] == "timeout"
        assert payload["return_code"] == -1
        assert "timed out" in payload["stderr"].lower()
    
    def test_execute_payload_writes_json_artifact(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that payload execution writes JSON artifact to disk."""
        request_data = {
            "command": "ls",
            "description": "List files"
        }
        
        response = client.post("/api/payloads", json=request_data)
        assert response.status_code == 200
        
        payload = response.json()
        payload_id = payload["payload_id"]
        
        # Verify JSON file was written
        json_path = tmp_results_dir / f"{payload_id}.json"
        assert json_path.exists()
        
        # Verify file contents
        with open(json_path, 'r') as f:
            stored_data = json.load(f)
        
        assert stored_data["payload_id"] == payload_id
        assert stored_data["command"] == "ls"
        assert stored_data["status"] == "completed"
    
    def test_execute_payload_collects_logs(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that payload execution collects logs during execution window."""
        request_data = {
            "command": "test-command",
            "description": "Test log collection"
        }
        
        response = client.post("/api/payloads", json=request_data)
        assert response.status_code == 200
        
        payload = response.json()
        
        # Verify logs are included
        assert "logs" in payload
        assert len(payload["logs"]) > 0
        
        # Verify log structure
        for log_type, log_summary in payload["logs"].items():
            assert "count" in log_summary
            assert "path" in log_summary
            assert "entries" in log_summary
            assert isinstance(log_summary["count"], int)
            assert log_summary["count"] >= 0
    
    def test_execute_payload_with_log_sources_filter(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test payload execution with log_sources filter."""
        request_data = {
            "command": "test-command",
            "description": "Test with filtered log sources",
            "log_sources": ["syslog"]
        }
        
        # Patch collect_logs to verify it receives the log_sources parameter
        with patch('agent_service.detection_agent_service.collect_logs') as mock_collect:
            # Set up a mock that tracks what parameters it was called with
            def collect_logs_with_tracking(start_time, end_time, log_sources=None):
                # Verify we received the correct log_sources
                assert log_sources == ["syslog"]
                
                # Return deterministic logs with only syslog
                return {
                    'syslog': {
                        'count': 2,
                        'entries': [
                            LogEntry(
                                timestamp=start_time,
                                source='/var/log/syslog',
                                host='localhost',
                                process='test',
                                pid=1000,
                                message='Test message',
                                raw_line='Raw line',
                                metadata={}
                            ),
                            LogEntry(
                                timestamp=start_time + timedelta(seconds=1),
                                source='/var/log/syslog',
                                host='localhost',
                                process='test',
                                pid=1000,
                                message='Test message 2',
                                raw_line='Raw line 2',
                                metadata={}
                            ),
                        ],
                        'path': '/var/log/syslog'
                    }
                }
            
            mock_collect.side_effect = collect_logs_with_tracking
            
            response = client.post("/api/payloads", json=request_data)
            
            assert response.status_code == 200
            payload = response.json()
            
            # Verify only syslog logs are included
            assert "logs" in payload
            assert "syslog" in payload["logs"]
            # Other log types should not be present
            assert "audit" not in payload["logs"]
            assert "auth" not in payload["logs"]
            assert "yum" not in payload["logs"]
    
    def test_execute_payload_with_environment_overrides(self, client, tmp_results_dir, mock_collect_logs, monkeypatch):
        """Test payload execution with environment variable overrides."""
        request_data = {
            "command": "echo $TEST_VAR",
            "description": "Test with environment override",
            "environment": {"TEST_VAR": "test_value"}
        }
        
        def mock_run(command, **kwargs):
            env = kwargs.get('env', {})
            # Verify environment was passed
            assert env.get('TEST_VAR') == 'test_value'
            
            mock_result = Mock()
            mock_result.stdout = "test_value"
            mock_result.stderr = ""
            mock_result.returncode = 0
            return mock_result
        
        with patch('subprocess.run', side_effect=mock_run):
            response = client.post("/api/payloads", json=request_data)
            assert response.status_code == 200


class TestGetPayloads:
    """Test cases for GET /api/payloads endpoint."""
    
    def test_get_payloads_empty_list(self, client, tmp_results_dir):
        """Test GET /api/payloads returns empty list initially."""
        response = client.get("/api/payloads")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 10
        assert data["items"] == []
    
    def test_get_payloads_pagination_metadata(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test pagination metadata in GET /api/payloads response."""
        # Create multiple payloads
        for i in range(5):
            request_data = {
                "command": f"command-{i}",
                "description": f"Test payload {i}"
            }
            response = client.post("/api/payloads", json=request_data)
            assert response.status_code == 200
        
        # Request page 1 with page_size=3
        response = client.get("/api/payloads?page=1&page_size=3")
        assert response.status_code == 200
        
        data = response.json()
        assert data["total"] == 5
        assert data["page"] == 1
        assert data["page_size"] == 3
        assert len(data["items"]) == 3
    
    def test_get_payloads_pagination_ordering(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that payloads are ordered by most recent first."""
        payload_ids = []
        
        # Create multiple payloads with delays
        for i in range(3):
            request_data = {
                "command": f"command-{i}",
                "description": f"Test payload {i}"
            }
            response = client.post("/api/payloads", json=request_data)
            payload_ids.append(response.json()["payload_id"])
        
        response = client.get("/api/payloads")
        assert response.status_code == 200
        
        data = response.json()
        items = data["items"]
        
        # Verify most recent items appear first
        # The last created payload should appear first
        assert items[0]["payload_id"] == payload_ids[-1]
        assert items[1]["payload_id"] == payload_ids[-2]
        assert items[2]["payload_id"] == payload_ids[0]
    
    def test_get_payloads_includes_log_counts(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that payload summaries include log counts."""
        request_data = {
            "command": "test-command",
            "description": "Test with logs"
        }
        
        response = client.post("/api/payloads", json=request_data)
        assert response.status_code == 200
        
        response = client.get("/api/payloads")
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["items"]) > 0
        
        item = data["items"][0]
        assert "log_counts" in item
        assert isinstance(item["log_counts"], dict)
        # Should have some log counts from mock
        assert len(item["log_counts"]) > 0
    
    def test_get_payloads_second_page(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test pagination on second page."""
        # Create 15 payloads
        for i in range(15):
            request_data = {
                "command": f"command-{i}",
                "description": f"Payload {i}"
            }
            response = client.post("/api/payloads", json=request_data)
            assert response.status_code == 200
        
        # Get page 2 with page_size=10
        response = client.get("/api/payloads?page=2&page_size=10")
        assert response.status_code == 200
        
        data = response.json()
        assert data["total"] == 15
        assert data["page"] == 2
        assert len(data["items"]) == 5
    
    def test_get_payloads_summary_fields(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that payload summaries include all required fields."""
        request_data = {
            "command": "test-command",
            "description": "Test payload"
        }
        
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        response = client.get("/api/payloads")
        assert response.status_code == 200
        
        data = response.json()
        summary = data["items"][0]
        
        # Verify all required fields are present
        assert summary["payload_id"] == payload_id
        assert summary["command"] == "test-command"
        assert summary["description"] == "Test payload"
        assert "status" in summary
        assert "timestamp" in summary
        assert "duration" in summary
        assert "return_code" in summary
        assert "log_counts" in summary
        assert "storage_path" in summary


class TestGetPayloadById:
    """Test cases for GET /api/payloads/{payload_id} endpoint."""
    
    def test_get_payload_by_id_success(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test retrieving a payload by ID."""
        # Create a payload
        request_data = {
            "command": "echo test",
            "description": "Test payload"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        # Retrieve it by ID
        response = client.get(f"/api/payloads/{payload_id}")
        
        assert response.status_code == 200
        payload = response.json()
        
        assert payload["payload_id"] == payload_id
        assert payload["command"] == "echo test"
        assert payload["description"] == "Test payload"
    
    def test_get_payload_by_id_expanded_record(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that GET /api/payloads/{payload_id} returns expanded record."""
        request_data = {
            "command": "test-command",
            "description": "Expanded record test"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        response = client.get(f"/api/payloads/{payload_id}")
        assert response.status_code == 200
        
        payload = response.json()
        
        # Verify expanded fields not in summary
        assert "stdout" in payload
        assert "stderr" in payload
        assert "return_code" in payload
        assert "logs" in payload
        assert isinstance(payload["logs"], dict)
        
        # Verify log entries are included
        for log_type, log_summary in payload["logs"].items():
            assert "count" in log_summary
            assert "path" in log_summary
            assert "entries" in log_summary
            assert isinstance(log_summary["entries"], list)
    
    def test_get_payload_by_id_not_found(self, client, tmp_results_dir):
        """Test 404 response for non-existent payload ID."""
        response = client.get("/api/payloads/nonexistent-id-12345")
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
    
    def test_get_payload_by_id_includes_all_fields(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that expanded record includes all required fields."""
        request_data = {
            "command": "test-command",
            "description": "Complete record test"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        response = client.get(f"/api/payloads/{payload_id}")
        assert response.status_code == 200
        
        payload = response.json()
        
        # Verify all required fields
        required_fields = [
            "payload_id",
            "command",
            "description",
            "status",
            "timestamp",
            "duration",
            "stdout",
            "stderr",
            "return_code",
            "logs",
            "storage_path"
        ]
        
        for field in required_fields:
            assert field in payload


class TestExportPayload:
    """Test cases for GET /api/payloads/{payload_id}/export endpoint."""
    
    def test_export_payload_success(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test exporting a payload returns file with correct headers."""
        # Create a payload
        request_data = {
            "command": "echo test",
            "description": "Export test"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        # Export it
        response = client.get(f"/api/payloads/{payload_id}/export")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert "attachment" in response.headers.get("content-disposition", "")
        assert f"payload_{payload_id}.json" in response.headers.get("content-disposition", "")
    
    def test_export_payload_file_contents(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that exported file contents match stored JSON."""
        # Create a payload
        request_data = {
            "command": "test-command",
            "description": "Content test"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        original_payload = response.json()
        
        # Export it
        response = client.get(f"/api/payloads/{payload_id}/export")
        assert response.status_code == 200
        
        # Parse the response content
        exported_data = response.json()
        
        # Compare with original
        assert exported_data["payload_id"] == original_payload["payload_id"]
        assert exported_data["command"] == original_payload["command"]
        assert exported_data["status"] == original_payload["status"]
    
    def test_export_payload_not_found(self, client, tmp_results_dir):
        """Test 404 response for non-existent export."""
        response = client.get("/api/payloads/nonexistent-id/export")
        
        assert response.status_code == 404
    
    def test_export_payload_file_identical(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test that exported file is identical to stored JSON."""
        request_data = {
            "command": "test-command",
            "description": "File identity test"
        }
        response = client.post("/api/payloads", json=request_data)
        payload_id = response.json()["payload_id"]
        
        # Read directly from filesystem
        stored_json_path = tmp_results_dir / f"{payload_id}.json"
        assert stored_json_path.exists()
        
        with open(stored_json_path, 'r') as f:
            stored_content = json.load(f)
        
        # Export through API
        response = client.get(f"/api/payloads/{payload_id}/export")
        assert response.status_code == 200
        exported_content = response.json()
        
        # Contents should match
        assert stored_content == exported_content


class TestLogSourcesFiltering:
    """Test cases for log_sources filter regression."""
    
    def test_log_sources_filter_only_requested_types(self, client, tmp_results_dir, mock_subprocess_success):
        """Test that only requested log sources are collected."""
        request_data = {
            "command": "test-command",
            "log_sources": ["syslog"]
        }
        
        with patch('agent_service.detection_agent_service.collect_logs') as mock_collect:
            # Track what was called
            call_args = []
            
            def track_call(start_time, end_time, log_sources=None):
                call_args.append({
                    'start_time': start_time,
                    'end_time': end_time,
                    'log_sources': log_sources
                })
                
                # Return only syslog
                return {
                    'syslog': {
                        'count': 1,
                        'entries': [
                            LogEntry(
                                timestamp=start_time,
                                source='/var/log/syslog',
                                host='localhost',
                                process='test',
                                pid=1000,
                                message='Test',
                                raw_line='Test',
                                metadata={}
                            )
                        ],
                        'path': '/var/log/syslog'
                    }
                }
            
            mock_collect.side_effect = track_call
            
            response = client.post("/api/payloads", json=request_data)
            assert response.status_code == 200
            
            # Verify collect_logs was called with correct log_sources
            assert len(call_args) > 0
            assert call_args[0]['log_sources'] == ['syslog']
            
            # Verify response only has syslog
            payload = response.json()
            assert 'syslog' in payload['logs']
            assert 'audit' not in payload['logs']
    
    def test_log_sources_filter_omits_other_types(self, client, tmp_results_dir, mock_subprocess_success):
        """Test that other log types are omitted when filtered."""
        request_data = {
            "command": "test-command",
            "log_sources": ["audit", "syslog"]
        }
        
        with patch('agent_service.detection_agent_service.collect_logs') as mock_collect:
            def return_filtered_logs(start_time, end_time, log_sources=None):
                results = {}
                if log_sources is None or 'audit' in log_sources:
                    results['audit'] = {
                        'count': 1,
                        'entries': [
                            LogEntry(
                                timestamp=start_time,
                                source='/var/log/audit/audit.log',
                                host='localhost',
                                process='kernel',
                                pid=0,
                                message='Audit event',
                                raw_line='Audit',
                                metadata={}
                            )
                        ],
                        'path': '/var/log/audit/audit.log'
                    }
                if log_sources is None or 'syslog' in log_sources:
                    results['syslog'] = {
                        'count': 1,
                        'entries': [
                            LogEntry(
                                timestamp=start_time,
                                source='/var/log/syslog',
                                host='localhost',
                                process='test',
                                pid=1000,
                                message='Syslog event',
                                raw_line='Syslog',
                                metadata={}
                            )
                        ],
                        'path': '/var/log/syslog'
                    }
                return results
            
            mock_collect.side_effect = return_filtered_logs
            
            response = client.post("/api/payloads", json=request_data)
            assert response.status_code == 200
            
            payload = response.json()
            # Should have audit and syslog
            assert 'audit' in payload['logs']
            assert 'syslog' in payload['logs']
            # Should not have auth and yum
            assert 'auth' not in payload['logs']
            assert 'yum' not in payload['logs']


class TestWriteAndReadPayloadJson:
    """Test cases for JSON file I/O functions."""
    
    def test_write_payload_json_creates_file(self, tmp_results_dir):
        """Test that write_payload_json creates a JSON file."""
        payload_data = {
            "payload_id": "test-123",
            "command": "test",
            "status": "completed",
            "stdout": "test output",
            "stderr": "",
            "return_code": 0,
            "logs": {},
            "storage_path": "/tmp/test.json"
        }
        
        # Need to patch get_results_directory for this direct call
        with patch('agent_service.detection_agent_service.get_results_directory', return_value=tmp_results_dir):
            result_path = write_payload_json("test-123", payload_data)
        
        assert result_path.exists()
        assert result_path.name == "test-123.json"
    
    def test_read_payload_json_returns_data(self, tmp_results_dir):
        """Test that read_payload_json reads and returns data."""
        payload_data = {
            "payload_id": "test-456",
            "command": "test-cmd",
            "status": "completed",
            "stdout": "output",
            "stderr": "",
            "return_code": 0,
            "logs": {},
            "storage_path": "/tmp/test.json"
        }
        
        with patch('agent_service.detection_agent_service.get_results_directory', return_value=tmp_results_dir):
            write_payload_json("test-456", payload_data)
            read_data = read_payload_json("test-456")
        
        assert read_data is not None
        assert read_data["payload_id"] == "test-456"
        assert read_data["command"] == "test-cmd"
    
    def test_read_payload_json_returns_none_for_missing(self, tmp_results_dir):
        """Test that read_payload_json returns None for missing files."""
        with patch('agent_service.detection_agent_service.get_results_directory', return_value=tmp_results_dir):
            result = read_payload_json("nonexistent-id")
        
        assert result is None


class TestDirectoryManagement:
    """Test cases for results directory management."""
    
    def test_get_results_directory_respects_env_var(self, tmp_path, monkeypatch):
        """Test that get_results_directory respects environment variable."""
        custom_dir = tmp_path / "custom_results"
        monkeypatch.setenv(RESULTS_DIR_ENV_VAR, str(custom_dir))
        
        result = get_results_directory()
        
        assert result == custom_dir
        assert custom_dir.exists()
    
    def test_get_results_directory_respects_legacy_env_var(self, tmp_path, monkeypatch):
        """Test that the legacy STATIC_RESULTS_DIR override is still honored."""
        legacy_dir = tmp_path / "legacy_results"
        monkeypatch.delenv(RESULTS_DIR_ENV_VAR, raising=False)
        monkeypatch.setenv(LEGACY_RESULTS_DIR_ENV_VAR, str(legacy_dir))
        
        result = get_results_directory()
        
        assert result == legacy_dir
        assert legacy_dir.exists()
    
    def test_get_results_directory_creates_directory(self, tmp_path, monkeypatch):
        """Test that get_results_directory creates the directory."""
        new_dir = tmp_path / "new_results" / "nested"
        monkeypatch.setenv(RESULTS_DIR_ENV_VAR, str(new_dir))
        
        assert not new_dir.exists()
        result = get_results_directory()
        
        assert result.exists()
        assert result == new_dir
    
    def test_get_results_directory_uses_default_without_env(self, tmp_path, monkeypatch):
        """Test that get_results_directory uses default when env not set."""
        monkeypatch.delenv(RESULTS_DIR_ENV_VAR, raising=False)
        monkeypatch.chdir(tmp_path)
        
        result = get_results_directory()
        
        assert result.name == "static_results"
        assert (tmp_path / "static_results").exists()


class TestIntegration:
    """Integration tests for complete workflows."""
    
    def test_complete_payload_workflow(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test complete workflow: create, list, retrieve, and export payload."""
        # Create payload
        create_response = client.post("/api/payloads", json={
            "command": "test-workflow",
            "description": "Integration test"
        })
        assert create_response.status_code == 200
        payload_id = create_response.json()["payload_id"]
        
        # List payloads
        list_response = client.get("/api/payloads")
        assert list_response.status_code == 200
        list_data = list_response.json()
        assert list_data["total"] == 1
        assert len(list_data["items"]) == 1
        
        # Retrieve payload
        get_response = client.get(f"/api/payloads/{payload_id}")
        assert get_response.status_code == 200
        get_data = get_response.json()
        assert get_data["payload_id"] == payload_id
        
        # Export payload
        export_response = client.get(f"/api/payloads/{payload_id}/export")
        assert export_response.status_code == 200
        export_data = export_response.json()
        assert export_data["payload_id"] == payload_id
    
    def test_multiple_payloads_workflow(self, client, tmp_results_dir, mock_collect_logs, mock_subprocess_success):
        """Test workflow with multiple payloads."""
        payload_ids = []
        
        # Create multiple payloads
        for i in range(5):
            response = client.post("/api/payloads", json={
                "command": f"cmd-{i}",
                "description": f"Payload {i}"
            })
            assert response.status_code == 200
            payload_ids.append(response.json()["payload_id"])
        
        # List all
        list_response = client.get("/api/payloads?page=1&page_size=10")
        assert list_response.status_code == 200
        list_data = list_response.json()
        assert list_data["total"] == 5
        assert len(list_data["items"]) == 5
        
        # Retrieve each one
        for payload_id in payload_ids:
            response = client.get(f"/api/payloads/{payload_id}")
            assert response.status_code == 200
            assert response.json()["payload_id"] == payload_id
