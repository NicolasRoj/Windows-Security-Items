# eventlog_gui.py
# Simple Windows Event Log GUI to query by Event ID(s) and lookback window.
# Python 3.13+, requires: pywin32. Run as Administrator to access Security log.

import os
import sys
import json
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import win32evtlog  # winevt APIs via pywin32
except ImportError:
    messagebox.showerror(
        "Missing dependency",
        "pywin32 is not installed.\n\nInstall with:\npy -3.13 -m pip install pywin32"
    )
    raise

APP_NAME = "eventlog_gui"
PROGRAM_DATA = os.environ.get("ProgramData", "") or str(Path(__file__).parent)
BASE_DIR = os.path.join(PROGRAM_DATA, APP_NAME)
os.makedirs(BASE_DIR, exist_ok=True)
JSON_PATH = os.path.join(BASE_DIR, "events.jsonl")

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def build_xpath(event_ids, lookback_ms: int) -> str:
    """
    event_ids: list[int]
    lookback_ms: milliseconds
    """
    if not event_ids:
        raise ValueError("At least one Event ID is required.")
    if len(event_ids) == 1:
        cond = f"(EventID={event_ids[0]})"
    else:
        ors = " or ".join([f"(EventID={i})" for i in event_ids])
        cond = f"({ors})"
    # <= must be XML-escaped as &lt;=
    return f"""<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[{cond} and TimeCreated[timediff(@SystemTime) &lt;= {lookback_ms}]]]</Select>
  </Query>
</QueryList>"""

def render_xml(evt_handle) -> str:
    return win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)

def parse_event(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    sysn = root.find("e:System", NS)
    datan = root.find("e:EventData", NS) or root.find("e:UserData", NS)
    out = {}

    if sysn is not None:
        rec_id_node = sysn.find("e:EventRecordID", NS)
        out["record_id"] = int(rec_id_node.text) if rec_id_node is not None and (rec_id_node.text or "").isdigit() else 0
        time_created = sysn.find("e:TimeCreated", NS)
        out["when_utc"] = time_created.get("SystemTime") if time_created is not None else None
        provider = sysn.find("e:Provider", NS)
        out["Provider"] = provider.get("Name") if provider is not None else ""
        eventid = sysn.find("e:EventID", NS)
        out["EventID"] = int(eventid.text) if eventid is not None and (eventid.text or "").isdigit() else None
        computer = sysn.find("e:Computer", NS)
        out["Computer"] = computer.text if computer is not None else ""

    # Flatten EventData (if present)
    fields = {}
    if datan is not None:
        for d in datan.findall("e:Data", NS):
            name = d.get("Name") or ""
            value = d.text or ""
            if name:
                fields[name] = value
        # Some providers use <Data> without Name—still capture
        if not fields:
            fields = {f"Data_{i}": (d.text or "") for i, d in enumerate(datan.findall("e:Data", NS))}
    out["Fields"] = fields
    return out

def append_jsonl(obj: dict) -> None:
    with open(JSON_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def run_query(event_ids, lookback_hours, output_widget: tk.Text, run_button: ttk.Button):
    """Worker thread: executes the query and prints results to the UI."""
    try:
        lookback_ms = int(float(lookback_hours) * 60 * 60 * 1000)
        xpath = build_xpath(event_ids, lookback_ms)
    except Exception as e:
        _ui_print(output_widget, f"[!] Parameter error: {e}\n")
        _enable_button(run_button)
        return

    _ui_print(output_widget, f"[*] Querying Security log for EventID(s) {event_ids} over last {lookback_hours}h...\n")

    try:
        h_query = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath, xpath)
    except Exception as e:
        # Extended status helps with XML issues or access denied
        try:
            ext = win32evtlog.EvtGetExtendedStatus()
        except Exception:
            ext = None
        msg = f"[!] EvtQuery failed: {e}"
        if ext:
            msg += f"\n    Extended: {ext}"
        if "Access is denied" in str(e):
            msg += "\n    Tip: Run this program as Administrator or grant 'Manage auditing and security log' to your user."
        _ui_print(output_widget, msg + "\n")
        _enable_button(run_button)
        return

    count = 0
    try:
        while True:
            try:
                events = win32evtlog.EvtNext(h_query, 64)
            except Exception as e:
                _ui_print(output_widget, f"[!] EvtNext failed: {e}\n")
                break
            if not events:
                break

            for ev in events:
                try:
                    xml = render_xml(ev)
                    rec = parse_event(xml)
                    count += 1
                    # Human-ish one-liner in UI
                    when = rec.get("when_utc", "?")
                    eid = rec.get("EventID", "?")
                    comp = rec.get("Computer", "?")
                    user = rec.get("Fields", {}).get("TargetDomainName", "") + "\\" + rec.get("Fields", {}).get("TargetUserName", "")
                    ip = rec.get("Fields", {}).get("IpAddress", "")
                    _ui_print(output_widget, f"[{count}] UTC={when} | EventID={eid} | {comp} | User={user} | IP={ip}\n")
                    # JSONL file for structured use
                    append_jsonl({"collected_at_utc": utc_now_iso(), **rec})
                except Exception as e:
                    _ui_print(output_widget, f"[!] Failed to parse event: {e}\n")
                finally:
                    try:
                        win32evtlog.EvtClose(ev)
                    except Exception:
                        pass
    finally:
        try:
            win32evtlog.EvtClose(h_query)
        except Exception:
            pass

    _ui_print(output_widget, f"\n[+] Done. Matched events: {count}\nSaved JSONL: {JSON_PATH}\n\n")
    _enable_button(run_button)

# ---------- UI helpers ----------
def _ui_print(widget: tk.Text, text: str):
    widget.configure(state="normal")
    widget.insert("end", text)
    widget.see("end")
    widget.configure(state="disabled")

def _disable_button(btn: ttk.Button):
    btn.configure(state="disabled")

def _enable_button(btn: ttk.Button):
    btn.configure(state="normal")

# ---------- GUI ----------
def main():
    root = tk.Tk()
    root.title("Windows Event Log Query (Security)")
    root.geometry("900x600")

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)

    # Inputs
    row = 0
    ttk.Label(frm, text="Event ID(s) (comma-separated):").grid(column=0, row=row, sticky="w")
    event_ids_var = tk.StringVar(value="4625")
    ttk.Entry(frm, textvariable=event_ids_var, width=40).grid(column=1, row=row, sticky="w")
    row += 1

    ttk.Label(frm, text="Lookback (hours):").grid(column=0, row=row, sticky="w")
    lookback_var = tk.StringVar(value="24")
    ttk.Entry(frm, textvariable=lookback_var, width=10).grid(column=1, row=row, sticky="w")
    row += 1

    ttk.Label(frm, text="Channel:").grid(column=0, row=row, sticky="w")
    ttk.Label(frm, text="Security (fixed)").grid(column=1, row=row, sticky="w")
    row += 1

    run_btn = ttk.Button(frm, text="Run Query")
    run_btn.grid(column=0, row=row, pady=8, sticky="w")

    open_dir_btn = ttk.Button(frm, text="Open Output Folder",
                              command=lambda: os.startfile(BASE_DIR) if os.name == "nt" else None)
    open_dir_btn.grid(column=1, row=row, pady=8, sticky="w")
    row += 1

    # Output box
    out = tk.Text(frm, height=25, wrap="none", state="disabled")
    out.grid(column=0, row=row, columnspan=2, sticky="nsew")
    frm.rowconfigure(row, weight=1)
    frm.columnconfigure(1, weight=1)

    # Scrollbars
    yscroll = ttk.Scrollbar(frm, orient="vertical", command=out.yview)
    yscroll.grid(column=2, row=row, sticky="ns")
    out.configure(yscrollcommand=yscroll.set)

    xscroll = ttk.Scrollbar(frm, orient="horizontal", command=out.xview)
    xscroll.grid(column=0, row=row+1, columnspan=2, sticky="ew")
    out.configure(xscrollcommand=xscroll.set)

    def on_run():
        # Parse Event IDs
        try:
            ids = [int(x.strip()) for x in event_ids_var.get().split(",") if x.strip()]
            if not ids:
                raise ValueError
        except Exception:
            messagebox.showerror("Input error", "Please enter one or more integer Event IDs (comma-separated).")
            return
        try:
            float(lookback_var.get())
        except Exception:
            messagebox.showerror("Input error", "Lookback hours must be a number.")
            return
        _disable_button(run_btn)
        threading.Thread(
            target=run_query,
            args=(ids, lookback_var.get(), out, run_btn),
            daemon=True
        ).start()

    run_btn.configure(command=on_run)

    # Tip banner
    _ui_print(out, f"Output will be saved to JSONL: {JSON_PATH}\n")
    _ui_print(out, "Tip: For Security log access, run this as Administrator or grant 'Manage auditing and security log'.\n\n")

    root.mainloop()

if __name__ == "__main__":
    main()
