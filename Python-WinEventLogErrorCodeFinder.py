# failed_logins_4625.py
# Collect Windows Security 4625 (failed logon) events from the last 24h.
# Python 3.13+, requires: pywin32
# Run as Administrator!

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

try:
    import win32evtlog  # winevt APIs via pywin32
except ImportError:
    print("FATAL: pywin32 not installed. Install with: py -3.13 -m pip install pywin32", file=sys.stderr)
    raise

APP_NAME = "failed_logins_4625"
DEFAULT_LOOKBACK_MS = 24 * 60 * 60 * 1000  # 24h in ms
BATCH_SIZE = 64

PROGRAM_DATA = os.environ.get("ProgramData", "")
BASE_DIR = os.path.join(PROGRAM_DATA, APP_NAME) if PROGRAM_DATA else os.path.join(os.path.dirname(__file__), APP_NAME)
os.makedirs(BASE_DIR, exist_ok=True)

LOG_PATH = os.path.join(BASE_DIR, "failed_logins.log")
JSON_PATH = os.path.join(BASE_DIR, "failed_logins.jsonl")
STATE_PATH = os.path.join(BASE_DIR, "state.json")

# ---------------- Logging ----------------
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
logger.handlers.clear()

_console = logging.StreamHandler(sys.stdout)
_console.setLevel(logging.INFO)
_console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(_console)

_file = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
_file.setLevel(logging.INFO)
_file.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
logger.addHandler(_file)

# ---------------- Utils ----------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def load_state() -> dict:
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_record_id": 0}

def save_state(state: dict) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)

def append_jsonl(obj: dict) -> None:
    with open(JSON_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def build_xpath(lookback_ms: int = DEFAULT_LOOKBACK_MS) -> str:
    # Path goes on <Select>, <= must be escaped as &lt;=
    return f"""<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= {lookback_ms}]]]</Select>
  </Query>
</QueryList>"""

# ---------------- XML Parsing ----------------
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def render_xml(evt_handle) -> str:
    return win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)

def parse_event_4625(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    sysn = root.find("e:System", NS)
    datan = root.find("e:EventData", NS)
    if sysn is None or datan is None:
        return {}

    rec_id_node = sysn.find("e:EventRecordID", NS)
    rec_id = int(rec_id_node.text) if rec_id_node is not None and (rec_id_node.text or "").isdigit() else 0
    time_created = sysn.find("e:TimeCreated", NS)
    when_utc = time_created.get("SystemTime") if time_created is not None else None

    fields = {}
    for d in datan.findall("e:Data", NS):
        name = d.get("Name")
        value = d.text or ""
        if name:
            fields[name] = value

    return {
        "record_id": rec_id,
        "when_utc": when_utc,
        "TargetUserName": fields.get("TargetUserName", ""),
        "TargetDomainName": fields.get("TargetDomainName", ""),
        "IpAddress": fields.get("IpAddress", ""),
        "WorkstationName": fields.get("WorkstationName", ""),
        "LogonType": fields.get("LogonType", ""),
        "Status": fields.get("Status", ""),
        "SubStatus": fields.get("SubStatus", ""),
        "FailureReason": fields.get("FailureReason", ""),
        "ProcessName": fields.get("ProcessName", ""),
        "TransmittedServices": fields.get("TransmittedServices", ""),
        "SubjectUserName": fields.get("SubjectUserName", ""),
        "SubjectDomainName": fields.get("SubjectDomainName", ""),
    }

# ---------------- Core ----------------
def collect_failed_logons_last_24h() -> int:
    state = load_state()
    last_seen = int(state.get("last_record_id", 0))
    xpath = build_xpath(DEFAULT_LOOKBACK_MS)

    try:
        h_query = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath, xpath)
    except Exception as e:
        try:
            ext = win32evtlog.EvtGetExtendedStatus()
        except Exception:
            ext = None
        msg = f"Failed to open Security log query: {e}"
        if ext:
            msg += f" | Extended: {ext}"
        logger.error(msg)
        return 0

    new_count = 0
    max_rec_id = last_seen

    try:
        while True:
            try:
                events = win32evtlog.EvtNext(h_query, BATCH_SIZE)
            except Exception as e:
                logger.error(f"EvtNext failed: {e}")
                break

            if not events:
                break

            for ev in events:
                try:
                    xml = render_xml(ev)
                    rec = parse_event_4625(xml)
                    rec_id = rec.get("record_id", 0)
                    if not rec_id:
                        continue
                    if rec_id <= last_seen:
                        continue

                    hr = (
                        f"Failed login (4625) | UTC={rec.get('when_utc','?')} | "
                        f"User={rec.get('TargetDomainName','?')}\\{rec.get('TargetUserName','?')} | "
                        f"IP={rec.get('IpAddress','?')} | WS={rec.get('WorkstationName','?')} | "
                        f"LogonType={rec.get('LogonType','?')} | Reason={rec.get('FailureReason','?')} | "
                        f"Status={rec.get('Status','?')}/{rec.get('SubStatus','?')} | RecID={rec_id}"
                    )
                    logger.info(hr)

                    rec_json = {"event": "4625_failed_logon", "collected_at_utc": utc_now_iso(), **rec}
                    append_jsonl(rec_json)

                    new_count += 1
                    if rec_id > max_rec_id:
                        max_rec_id = rec_id

                except Exception as e:
                    logger.error(f"Failed to parse/render event: {e}")
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

    if max_rec_id > last_seen:
        state["last_record_id"] = max_rec_id
        save_state(state)

    return new_count

def main():
    if os.name != "nt":
        logger.error("This script must run on Windows.")
        sys.exit(1)

    logger.info(f"Starting {APP_NAME} (last 24h, Security log)")
    count = collect_failed_logons_last_24h()
    logger.info(f"Done. New events: {count}.")
    logger.info(f"Logs: {LOG_PATH}")
    logger.info(f"JSON: {JSON_PATH}")
    logger.info(f"State: {STATE_PATH}")

if __name__ == "__main__":
    main()

