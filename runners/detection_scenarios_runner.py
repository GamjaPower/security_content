#!/usr/bin/env python3
"""Run a Splunk query and print results.

예제:
  python runners/detection_scenarios_runner.py --username admin --password changeme \
      --query 'search index=_internal | head 3' --no-ssl-verify
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('./.env', override=True)

try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
except ImportError:
    sys.stderr.write(
        "splunklib SDK not installed. Install with: pip install splunk-sdk\n"
    )
    raise


def parse_raw_payload(raw_payload):
    """Parse raw JSON payload from Splunk job results and extract the 'results' list."""
    if not raw_payload:
        return None
    try:
        if isinstance(raw_payload, bytes):
            raw_text = raw_payload.decode("utf-8", errors="replace")
        else:
            raw_text = raw_payload
        payload = json.loads(raw_text)
        parsed = payload.get("results")
        if isinstance(parsed, list):
            return parsed
        elif parsed is None and "preview" in payload and "results" in payload:
            return []
        else:
            return None
    except Exception as parse_exc:
        sys.stderr.write(f"Unable to parse raw Splunk results payload: {parse_exc}\n")
        return None


def run_splunk_search(
    host,
    port,
    query,
    token,
    scheme="https",
    verify_ssl=True,
    earliest_time="-24h",
    latest_time="now",
):
    if not token:
        raise ValueError("Splunk token is required for authentication")

    # splunklib may not honor Python's global SSL context; ensure (optional)
    # disable verification if requested.
    if not verify_ssl:
        import ssl

        os.environ.setdefault("PYTHONHTTPSVERIFY", "0")
        try:
            ssl._create_default_https_context = ssl._create_unverified_context
        except AttributeError:
            pass

    connect_args = {
        "host": host,
        "port": port,
        "scheme": scheme,
        "app": "search",
        "token": token,
    }

    # splunklib client supports verify=False to disable certificate check.
    if not verify_ssl:
        connect_args["verify"] = False

    service = splunk_client.connect(**connect_args)

    job = service.jobs.create(
        query,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode="blocking",
        output_mode="json",
    )

    reader = splunk_results.JSONResultsReader(job.results())

    results = []
    raw_payload = None
    try:
        for item in reader:
            if isinstance(item, dict):
                results.append(item)
            elif isinstance(item, splunk_results.Message):
                sys.stderr.write(f"Splunk message: {item.type} - {item.message}\n")
    except Exception as exc:
        # splunklib may raise JSONDecodeError when no/invalid JSON payload is returned.
        # Keep exception context and handle parsing outside the except block.
        # sys.stderr.write(f"Warning: failed to parse Splunk results in reader loop: {exc}\n")
        try:
            raw_payload = job.results(output_mode="json").read()
            #sys.stderr.write(f"Raw splunk results payload: {raw_payload!r}\n")
        except Exception as read_exc:
            sys.stderr.write(f"Unable to read raw Splunk results payload: {read_exc}\n")

    # Fallback parsing from raw payload, moved out of broad except handler.
    if not results and raw_payload:
        parsed_results = parse_raw_payload(raw_payload)
        if parsed_results is not None:
            results = parsed_results

    return results


def main():

    load_dotenv()
    parser = argparse.ArgumentParser(description="Run SPL on Splunk and print output")
    parser.add_argument("--host", default="192.168.0.102", help="Splunk host")
    parser.add_argument("--port", default=8089, type=int, help="Splunk management port")
    parser.add_argument("--scheme", default="https", choices=["https", "http"], help="URL scheme for Splunk (https or http)")
    parser.add_argument("--token", default=os.getenv("SPLUNK_TOKEN"), required=False, help="Splunk auth token (or set SPLUNK_TOKEN in .env)")
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument("--earliest", default="-24h", help="earliest time")
    parser.add_argument("--latest", default="now", help="latest time")
    parser.add_argument(
        "--max-events",
        type=int,
        default=10,
        help="Max detection queries to run (0 for all, default 10)",
    )

    args = parser.parse_args()

    # Load query from detections_v2.json and use it, no --query option anymore
    detections_file = os.path.join(os.path.dirname(__file__), "detections_v2.json")
    query = None
    detection_name = None
    if os.path.exists(detections_file):
        try:
            with open(detections_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            detections = data.get("detections", [])
            if detections:
                first_detection = detections[0]
                query = first_detection.get("search")
                if query:
                    query = query.replace('\n', ' ')
                    detection_name = first_detection.get('name', 'Unknown')
                    print(f"Using query from detection: {detection_name}")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load detections from {detections_file}: {e}\n")

    if not query:
        parser.error("No query found in detections_v2.json. --query option is removed.")

    token = args.token or os.getenv("SPLUNK_TOKEN")
    if not token:
        parser.error("--token is required if SPLUNK_TOKEN environment variable is not set")

    # Determine which detections to execute
    if detection_name is None:
        parser.error("No query found in detections_v2.json. --query option is removed.")

    # Find selected detections
    with open(detections_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    all_detections = data.get("detections", [])
    max_runs = args.max_events
    if max_runs < 0:
        parser.error("--max-events must be 0 or positive")
    selected_detections = all_detections if max_runs == 0 else all_detections[:max_runs]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    all_results = []

    for idx, det in enumerate(selected_detections, start=1):
        current_name = det.get("name", f"detection_{idx}")
        current_query = det.get("search")
        if not current_query:
            print(f"Skipping detection without query: {current_name}")
            continue

        current_query = current_query.replace("\n", " ")
        if current_query.startswith("|"):
            pass
        else:
            current_query = f"search {current_query}"

        # print(f"current_query: {current_query}")
        try:
            results = run_splunk_search(
                host=args.host,
                port=args.port,
                query=current_query,
                token=token,
                scheme=args.scheme,
                verify_ssl=not args.no_ssl_verify,
                earliest_time=args.earliest,
                latest_time=args.latest,
            )
        except Exception as exc:
            sys.stderr.write(f"Error running detection '{current_name}' Exception: {exc} \n")
            results = None

        if results:
            for row in results:
                row_copy = dict(row)
                row_copy["detection_name"] = current_name
                all_results.append(row_copy)
            print(f"{len(results)} | {current_name}")
        else:
            print(f"0 | {current_name}")

    filename = f"detections.{timestamp}.csv"
    if all_results:
        fieldnames = sorted({k for row in all_results for k in row.keys()})
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
    else:
        # create empty file if no results
        open(filename, 'w', encoding='utf-8').close()


if __name__ == "__main__":
    main()
