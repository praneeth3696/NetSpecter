"""
NetSpecter FastAPI Backend Application
======================================
REST API, WebSocket Hub, and Static Asset Server for NetSpecter Cyber-Terminal Web UI.
"""

from __future__ import annotations
import asyncio
import io
import os
import tempfile
import time
import webbrowser
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from core.models import DetectionResult, SessionStats
from core.web.bridge import bridge
from reporting.reporter import export_json, export_jsonl, generate_html_report

app = FastAPI(
    title="NetSpecter Cyber Terminal API",
    description="Real-Time Network Insecurity & Credential Leak Auditor",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Determine static files directory
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "web", "static"))


@app.on_event("startup")
async def on_startup():
    loop = asyncio.get_running_loop()
    bridge.set_loop(loop)


@app.get("/api/status")
async def get_status():
    return {
        "is_capturing": bridge.is_capturing,
        "active_iface": bridge.active_iface or "auto",
        "bpf_filter": bridge.bpf_filter,
        "stats": bridge.get_stats_dict(),
        "total_detections": len(bridge.detections),
        "flows": bridge.get_active_flows_list()
    }


@app.get("/api/interfaces")
async def get_interfaces():
    try:
        from scapy.all import conf
        interfaces = []
        if hasattr(conf, "ifaces") and conf.ifaces:
            for key, iface in conf.ifaces.items():
                name = getattr(iface, "name", str(key))
                ip = getattr(iface, "ip", "–") or "–"
                mac = getattr(iface, "mac", "–") or "–"
                desc = getattr(iface, "description", "")
                status = "Loopback" if "loopback" in str(desc).lower() or "lo" in name.lower() else (
                    "Active" if ip and ip != "0.0.0.0" and ip != "–" else "Standby"
                )
                interfaces.append({
                    "name": name,
                    "ip": ip,
                    "mac": mac,
                    "description": desc or status,
                    "status": status
                })
        return {"interfaces": interfaces}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


@app.post("/api/scan/start")
async def start_scan(data: dict):
    iface = data.get("iface")
    bpf = data.get("bpf")
    success = bridge.start_capture(iface=iface, bpf=bpf)
    return {"success": success, "is_capturing": bridge.is_capturing, "iface": bridge.active_iface}


@app.post("/api/scan/stop")
async def stop_scan():
    bridge.stop_capture()
    return {"success": True, "is_capturing": False, "stats": bridge.get_stats_dict()}


@app.post("/api/simulate")
async def simulate_leak(data: dict):
    scenario = data.get("scenario", "http")
    result = bridge.simulate_leak(scenario)
    return {"success": True, "scenario": scenario, "result": result}


@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload .pcap or .pcapng")

    content = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        tf.write(content)
        temp_path = tf.name

    try:
        from scapy.all import rdpcap
        from sniffer import SnifferEngine

        pcap_engine = SnifferEngine(mask_secrets=False, use_dashboard=False)
        packets = rdpcap(temp_path)
        for pkt in packets:
            pcap_engine.process_packet(pkt)

        # Merge findings into web view format
        formatted_leaks = [
            bridge._format_detection_for_web(d) for d in pcap_engine.detections
        ]

        # Also push to bridge detections so user can export
        for d in pcap_engine.detections:
            bridge.detections.append(d)
            bridge.stats.record_detection(d)

        return {
            "success": True,
            "filename": file.filename,
            "packets_count": len(packets),
            "leaks_count": len(pcap_engine.detections),
            "leaks": formatted_leaks,
            "stats": {
                "inspected": pcap_engine.stats.packets_inspected,
                "alerts": pcap_engine.stats.alerts_count,
                "protocols": pcap_engine.stats.protocol_counts,
                "severities": {
                    "critical": sum(1 for d in pcap_engine.detections if d.severity == "CRITICAL"),
                    "high": sum(1 for d in pcap_engine.detections if d.severity == "HIGH"),
                    "medium": sum(1 for d in pcap_engine.detections if d.severity == "MEDIUM"),
                }
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {e}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.get("/api/export/{fmt}")
async def export_report(fmt: str, mask: bool = True):
    if fmt == "json":
        data = [d.to_dict(mask=mask) for d in bridge.detections]
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": "attachment; filename=netspecter_audit.json"}
        )
    elif fmt == "jsonl":
        lines = [d.to_dict(mask=mask) for d in bridge.detections]
        import json
        content = "\n".join(json.dumps(l) for l in lines)
        return PlainTextResponse(
            content=content,
            headers={"Content-Disposition": "attachment; filename=netspecter_audit.jsonl"}
        )
    elif fmt == "html":
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            html_path = tf.name
        generate_html_report(bridge.detections, bridge.stats, html_path, mask=mask)
        return FileResponse(
            html_path,
            filename="netspecter_executive_report.html",
            media_type="text/html"
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use json, jsonl, or html")


@app.websocket("/ws/live")
async def websocket_live_endpoint(ws: WebSocket):
    await bridge.connect_socket(ws)
    try:
        while True:
            # Client can send commands via WS
            data = await ws.receive_json()
            cmd = data.get("action")
            if cmd == "start":
                bridge.start_capture(iface=data.get("iface"), bpf=data.get("bpf"))
            elif cmd == "stop":
                bridge.stop_capture()
            elif cmd == "simulate":
                bridge.simulate_leak(data.get("scenario", "http"))
    except WebSocketDisconnect:
        bridge.disconnect_socket(ws)
    except Exception:
        bridge.disconnect_socket(ws)


# Mount static assets
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


def start_web_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
    iface: Optional[str] = None
) -> None:
    """Launches the NetSpecter fullstack web server and opens default browser."""
    if iface:
        bridge.active_iface = iface

    url = f"http://{host}:{port}"
    
    if open_browser:
        def _open():
            time.sleep(0.8)
            webbrowser.open(url)
        import threading
        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False
    )
