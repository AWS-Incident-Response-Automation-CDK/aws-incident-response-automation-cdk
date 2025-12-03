import json
import boto3
import gzip
import re
import os
from datetime import datetime, timezone

s3 = boto3.client("s3")
firehose= boto3.client("firehose")

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
SOURCE_PREFIX = "exportedlogs/vpc-dns-logs/"
FIREHOSE_STREAM_NAME = os.environ.get("FIREHOSE_STREAM_NAME")

VPC_RE = re.compile(r"/(vpc-[0-9A-Za-z\-]+)")
ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")

def read_gz(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=obj["Body"]) as f:
        return f.read().decode("utf-8", errors="replace")

def flatten_once(d):
    out = {}
    for k, v in (d or {}).items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                out[f"{k}_{k2}"] = v2
        else:
            out[k] = v
    return out


def safe_int(x):
    try:
        return int(x)
    except:
        return None

def parse_dns_line(line):
    raw = line.strip()
    if not raw:
        return None

    json_part = raw
    prefix_ts = None

    if ISO_TS_RE.match(raw):
        try:
            prefix_ts, rest = raw.split(" ", 1)
            json_part = rest
        except:
            pass

    if not json_part.startswith("{"):
        idx = json_part.find("{")
        if idx != -1:
            json_part = json_part[idx:]

    try:
        obj = json.loads(json_part)
    except:
        return None

    flat = flatten_once(obj)
    if prefix_ts:
        flat["_prefix_ts"] = prefix_ts
    return flat


def lambda_handler(event, context):
    print(f"Received S3 Event. Records: {len(event.get('Records', []))}")
    
    firehose_records = []

    for record in event.get("Records", []):
        if "s3" not in record: 
            continue

        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        
        if not key.startswith(SOURCE_PREFIX) or not key.endswith(".gz"):
            print(f"Skipping file: {key}")
            continue

        print(f"Processing S3 file: {key}")
        
        # Extract VPC ID from file path
        vpc_id_match = VPC_RE.search(key)
        vpc_id = vpc_id_match.group(1) if vpc_id_match else "unknown"

        # Read and process file content
        content = read_gz(bucket, key)
        if not content: 
            continue
        
        for line in content.splitlines():
            r = parse_dns_line(line)
            if not r: 
                continue
            
            # Create flattened JSON record
            out = {
                "version": r.get("version"),
                "account_id": r.get("account_id"),
                "region": r.get("region"),
                "vpc_id": r.get("vpc_id", vpc_id),
                "query_timestamp": r.get("query_timestamp"),
                "query_name": r.get("query_name"),
                "query_type": r.get("query_type"),
                "query_class": r.get("query_class"),
                "rcode": r.get("rcode"),
                "answers": json.dumps(r.get("answers"), ensure_ascii=False),
                "srcaddr": r.get("srcaddr"),
                "srcport": safe_int(r.get("srcport")),
                "transport": r.get("transport"),
                "srcids_instance": r.get("srcids_instance"),
                "timestamp": (r.get("query_timestamp") or r.get("timestamp") or r.get("_prefix_ts"))
            }
            
            # Add newline for JSONL format
            json_row = json.dumps(out, ensure_ascii=False) + "\n"
            firehose_records.append({'Data': json_row})

    # Send to Firehose in batches of 500
    if firehose_records:
        total_records = len(firehose_records)
        print(f"Sending {total_records} records to Firehose...")
        
        batch_size = 500
        for i in range(0, total_records, batch_size):
            batch = firehose_records[i:i + batch_size]
            try:
                response = firehose.put_record_batch(
                    DeliveryStreamName=FIREHOSE_STREAM_NAME,
                    Records=batch
                )
                if response['FailedPutCount'] > 0:
                    print(f"Warning: {response['FailedPutCount']} records failed")
            except Exception as e:
                print(f"Firehose error: {e}")

    return {"status": "ok", "total_records": len(firehose_records)}