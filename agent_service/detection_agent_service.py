"""
FastAPI service for detection agent payload execution and log collection.

Provides endpoints for:
- Agent management
- Payload execution with log collection
- Payload history and retrieval
- Export functionality
"""

import json
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from agent_service.log_parser import LogEntry, collect_logs


RESULTS_DIR_ENV_VAR = "AGENT_RESULTS_DIR"
LEGACY_RESULTS_DIR_ENV_VAR = "STATIC_RESULTS_DIR"
DEFAULT_RESULTS_DIR = "static_results"


class AgentMetadata(BaseModel):
    """Agent metadata information."""
    agent_id: str
    hostname: str
    status: str
    last_seen: datetime
    ip_address: Optional[str] = None


class PayloadExecutionRequest(BaseModel):
    """Request model for payload execution."""
    command: str = Field(..., description="Shell command to execute")
    description: Optional[str] = Field(None, description="Optional description of the payload")
    log_sources: Optional[List[str]] = Field(None, description="Specific log sources to collect (e.g., ['audit', 'syslog'])")
    environment: Optional[Dict[str, str]] = Field(None, description="Optional environment variable overrides")


class LogSummary(BaseModel):
    """Summary of logs collected for a specific source."""
    count: int
    path: str
    entries: List[Dict]


class PayloadRecord(BaseModel):
    """Complete payload execution record."""
    payload_id: str
    command: str
    description: Optional[str] = None
    status: str
    timestamp: datetime
    duration: float
    stdout: str
    stderr: str
    return_code: int
    logs: Dict[str, LogSummary]
    storage_path: str


class PayloadSummary(BaseModel):
    """Lightweight payload summary for list view."""
    payload_id: str
    command: str
    description: Optional[str] = None
    status: str
    timestamp: datetime
    duration: float
    return_code: int
    log_counts: Dict[str, int]
    storage_path: str


class PayloadListResponse(BaseModel):
    """Paginated payload history response."""
    total: int
    page: int
    page_size: int
    items: List[PayloadSummary]


app = FastAPI(title="Detection Agent Service", version="1.0.0")


def get_results_directory() -> Path:
    """
    Get the results directory path with environment variable override support.
    
    Returns:
        Path object for the results directory
    """
    configured_dir = (
        os.environ.get(RESULTS_DIR_ENV_VAR)
        or os.environ.get(LEGACY_RESULTS_DIR_ENV_VAR)
        or DEFAULT_RESULTS_DIR
    )
    path = Path(configured_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_command(command: str, env_overrides: Optional[Dict[str, str]] = None, timeout: int = 30) -> Dict[str, Union[str, int]]:
    """
    Execute a shell command with a timeout.
    
    Args:
        command: Shell command to execute
        env_overrides: Optional environment variable overrides
        timeout: Timeout in seconds (default 30)
        
    Returns:
        Dictionary containing stdout, stderr, return_code, and status
    """
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )
        
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode,
            'status': 'completed' if result.returncode == 0 else 'failed'
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        timeout_message = f'Command timed out after {timeout} seconds'
        stderr = f"{stderr}\n{timeout_message}".strip() if stderr else timeout_message
        return {
            'stdout': stdout,
            'stderr': stderr,
            'return_code': -1,
            'status': 'timeout'
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'Error executing command: {str(e)}',
            'return_code': -2,
            'status': 'failed'
        }


def serialize_log_entry(entry: LogEntry) -> Dict:
    """
    Serialize a LogEntry object to a JSON-compatible dictionary.
    
    Args:
        entry: LogEntry object to serialize
        
    Returns:
        Dictionary representation of the log entry
    """
    return {
        'timestamp': entry.timestamp.isoformat(),
        'source': entry.source,
        'host': entry.host,
        'process': entry.process,
        'pid': entry.pid,
        'message': entry.message,
        'raw_line': entry.raw_line,
        'metadata': entry.metadata
    }


def write_payload_json(payload_id: str, payload_data: Dict, directory: Optional[Path] = None) -> Path:
    """
    Write payload data to a JSON file.
    
    Args:
        payload_id: Unique identifier for the payload
        payload_data: Payload data to write
        directory: Optional directory path override
        
    Returns:
        Path to the written file
    """
    results_dir = directory or get_results_directory()
    file_path = results_dir / f"{payload_id}.json"
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(payload_data, f, indent=2, ensure_ascii=False)
    
    return file_path


def read_payload_json(payload_id: str, directory: Optional[Path] = None) -> Optional[Dict]:
    """
    Read payload data from a JSON file.
    
    Args:
        payload_id: Unique identifier for the payload
        directory: Optional directory path override
        
    Returns:
        Payload data dictionary or None if not found
    """
    results_dir = directory or get_results_directory()
    file_path = results_dir / f"{payload_id}.json"
    
    if not file_path.exists():
        return None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_all_payload_files() -> List[Path]:
    """
    Get all payload JSON files sorted by modification time (newest first).
    
    Returns:
        List of Path objects for payload files
    """
    results_dir = get_results_directory()
    
    if not results_dir.exists():
        return []
    
    files = list(results_dir.glob('*.json'))
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    
    return files


@app.get("/api/agents", response_model=List[AgentMetadata])
def get_agents():
    """
    Get list of available agents.
    
    Returns seeded list containing at least the localhost agent.
    """
    return [
        AgentMetadata(
            agent_id="localhost",
            hostname="localhost",
            status="online",
            last_seen=datetime.now(),
            ip_address="127.0.0.1"
        )
    ]


@app.post("/api/payloads", response_model=PayloadRecord)
def execute_payload(request: PayloadExecutionRequest):
    """
    Execute a payload command and collect logs.
    
    Synchronously runs the command, captures output, collects logs from the
    time window around execution, and persists the full payload record to disk.
    """
    payload_id = str(uuid.uuid4())
    start_time = datetime.now()
    results_dir = get_results_directory()
    
    # Execute the command
    execution_start = datetime.now()
    result = run_command(request.command, request.environment)
    execution_end = datetime.now()
    
    duration = (execution_end - execution_start).total_seconds()
    
    # Collect logs from the execution time window
    logs_result = collect_logs(
        start_time=start_time,
        end_time=execution_end,
        log_sources=request.log_sources
    )
    
    # Organize logs with counts and serialized entries
    logs_summary = {}
    for log_type, log_data in logs_result.items():
        logs_summary[log_type] = {
            'count': log_data['count'],
            'path': log_data['path'],
            'entries': [serialize_log_entry(entry) for entry in log_data['entries']]
        }
    
    storage_path = str(results_dir / f"{payload_id}.json")
    
    # Create payload record
    payload_data = {
        'payload_id': payload_id,
        'command': request.command,
        'description': request.description,
        'status': result['status'],
        'timestamp': start_time.isoformat(),
        'duration': duration,
        'stdout': result['stdout'],
        'stderr': result['stderr'],
        'return_code': result['return_code'],
        'logs': logs_summary,
        'storage_path': storage_path
    }
    
    # Persist to disk
    write_payload_json(payload_id, payload_data, directory=results_dir)
    
    # Convert logs to Pydantic models for response
    logs_response = {}
    for log_type, log_summary in logs_summary.items():
        logs_response[log_type] = LogSummary(**log_summary)
    
    return PayloadRecord(
        payload_id=payload_id,
        command=request.command,
        description=request.description,
        status=result['status'],
        timestamp=start_time,
        duration=duration,
        stdout=result['stdout'],
        stderr=result['stderr'],
        return_code=result['return_code'],
        logs=logs_response,
        storage_path=storage_path
    )


@app.get("/api/payloads", response_model=PayloadListResponse)
def get_payloads(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Page size")
):
    """
    Get paginated payload history.
    
    Returns lightweight summaries of payload executions, sorted by most recent.
    """
    files = get_all_payload_files()
    total_count = len(files)
    
    # Calculate pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    paginated_files = files[start_idx:end_idx]
    
    summaries = []
    for file_path in paginated_files:
        try:
            payload_data = read_payload_json(file_path.stem)
            if payload_data:
                # Extract log counts
                log_counts = {}
                if 'logs' in payload_data:
                    for log_type, log_data in payload_data['logs'].items():
                        log_counts[log_type] = log_data.get('count', 0)
                
                summaries.append(PayloadSummary(
                    payload_id=payload_data['payload_id'],
                    command=payload_data['command'],
                    description=payload_data.get('description'),
                    status=payload_data['status'],
                    timestamp=datetime.fromisoformat(payload_data['timestamp']),
                    duration=payload_data['duration'],
                    return_code=payload_data['return_code'],
                    log_counts=log_counts,
                    storage_path=payload_data['storage_path']
                ))
        except Exception:
            # Skip files that can't be read
            continue
    
    return PayloadListResponse(
        total=total_count,
        page=page,
        page_size=page_size,
        items=summaries
    )


@app.get("/api/payloads/{payload_id}", response_model=PayloadRecord)
def get_payload(payload_id: str):
    """
    Get full payload record by ID.
    
    Returns the complete JSON document for the specified payload.
    """
    payload_data = read_payload_json(payload_id)
    
    if not payload_data:
        raise HTTPException(status_code=404, detail="Payload not found")
    
    # Convert logs to Pydantic models
    logs_response = {}
    if 'logs' in payload_data:
        for log_type, log_summary in payload_data['logs'].items():
            logs_response[log_type] = LogSummary(**log_summary)
    
    return PayloadRecord(
        payload_id=payload_data['payload_id'],
        command=payload_data['command'],
        description=payload_data.get('description'),
        status=payload_data['status'],
        timestamp=datetime.fromisoformat(payload_data['timestamp']),
        duration=payload_data['duration'],
        stdout=payload_data['stdout'],
        stderr=payload_data['stderr'],
        return_code=payload_data['return_code'],
        logs=logs_response,
        storage_path=payload_data['storage_path']
    )


@app.get("/api/payloads/{payload_id}/export")
def export_payload(payload_id: str):
    """
    Export payload as a downloadable JSON file.
    
    Streams the stored JSON file with appropriate Content-Disposition header.
    """
    results_dir = get_results_directory()
    file_path = results_dir / f"{payload_id}.json"
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Payload not found")
    
    return FileResponse(
        path=str(file_path),
        media_type='application/json',
        filename=f"payload_{payload_id}.json",
        headers={"Content-Disposition": f"attachment; filename=payload_{payload_id}.json"}
    )
