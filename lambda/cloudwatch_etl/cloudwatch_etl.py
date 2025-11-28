import json
import boto3
import gzip
import re
import os
from datetime import datetime, timezone

s3 = boto3.client("s3")
glue = boto3.client("glue")

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
SOURCE_BUCKET = os.environ.get("SOURCE_BUCKET", "cloudwatch-autoexport-bucket")
SOURCE_PREFIX = "exportedlogs/vpc-dns-logs/"

DEST_BUCKET = os.environ.get("DEST_BUCKET", "cloudwatch-etl-bucket")
DATABASE_NAME = os.environ.get("DATABASE_NAME", "cloudwatch_etl_db")
TABLE_NAME = os.environ.get("TABLE_NAME", "vpc_dns_logs")

VPC_RE = re.compile(r"/(vpc-[0-9A-Za-z\-]+)")
ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")

GLUE_COLUMNS = [
    {"Name": "version", "Type": "string"},
    {"Name": "account_id", "Type": "string"},
    {"Name": "region", "Type": "string"},
    {"Name": "vpc_id", "Type": "string"},
    {"Name": "query_timestamp", "Type": "string"},
    {"Name": "query_name", "Type": "string"},
    {"Name": "query_type", "Type": "string"},
    {"Name": "query_class", "Type": "string"},
    {"Name": "rcode", "Type": "string"},
    {"Name": "answers", "Type": "string"},
    {"Name": "srcaddr", "Type": "string"},
    {"Name": "srcport", "Type": "int"},
    {"Name": "transport", "Type": "string"},
    {"Name": "srcids_instance", "Type": "string"},
    {"Name": "timestamp", "Type": "string"}
]

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


def ensure_partition(partition_value):
    try:
        glue.get_partition(
            DatabaseName=DATABASE_NAME,
            TableName=TABLE_NAME,
            PartitionValues=[partition_value]
        )
        return
    except glue.exceptions.EntityNotFoundException:
        pass

    glue.create_partition(
        DatabaseName=DATABASE_NAME,
        TableName=TABLE_NAME,
        PartitionInput={
            "Values": [partition_value],
            "StorageDescriptor": {
                "Columns": GLUE_COLUMNS,
                "Location": f"s3://{DEST_BUCKET}/vpc-logs/date={partition_value}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.openx.data.jsonserde.JsonSerDe"
                },
            }
        }
    )
    print("Created partition:", partition_value)


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
    print("Event received:", json.dumps(event))

    if "Records" not in event:
        return {"statusCode": 400, "body": "Invalid S3 event"}

    files_to_process = []
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        if key.startswith(SOURCE_PREFIX) and key.endswith(".gz"):
            files_to_process.append((bucket, key))
        else:
            print(f"Skipping: {key}")

    if not files_to_process:
        return {"statusCode": 200, "body": "No matching files"}

    processed_count = 0
    
    for bucket, key in files_to_process:
        print(f"Processing file: {key}")
        
        original_filename = os.path.basename(key) 
        
        new_filename = original_filename.replace(".gz", ".jsonl.gz")

        vpc_id_match = VPC_RE.search(key)
        vpc_id = vpc_id_match.group(1) if vpc_id_match else "unknown"

        text_content = read_gz(bucket, key)
        parsed_records = []
        
        for line in text_content.splitlines():
            rec = parse_dns_line(line)
            if rec:
                parsed_records.append(rec)
        
        if not parsed_records:
            print(f"No records found in {key}")
            continue

        final_data = []
        for r in parsed_records:
            out = {c["Name"]: None for c in GLUE_COLUMNS}
            out["version"] = r.get("version")
            out["account_id"] = r.get("account_id")
            out["region"] = r.get("region")
            out["vpc_id"] = r.get("vpc_id", vpc_id)
            out["query_timestamp"] = r.get("query_timestamp")
            out["query_name"] = r.get("query_name")
            out["query_type"] = r.get("query_type")
            out["query_class"] = r.get("query_class")
            out["rcode"] = r.get("rcode")
            out["answers"] = json.dumps(r.get("answers"), ensure_ascii=False)
            out["srcaddr"] = r.get("srcaddr")
            out["srcport"] = safe_int(r.get("srcport"))
            out["transport"] = r.get("transport")
            out["srcids_instance"] = r.get("srcids_instance")
            out["timestamp"] = (r.get("query_timestamp") or r.get("timestamp") or r.get("_prefix_ts"))
            final_data.append(out)

        partition_value = final_data[0]["timestamp"][:10]
        dest_key = f"vpc-logs/date={partition_value}/{new_filename}"
        
        json_body = "\n".join(json.dumps(r, ensure_ascii=False) for r in final_data)
        compressed_body = gzip.compress(json_body.encode("utf-8"))
        
        s3.put_object(
            Bucket=DEST_BUCKET,
            Key=dest_key,
            Body=compressed_body,
            ContentType="application/x-ndjson",
            ContentEncoding="gzip" 
        )
        print(f"--> Uploaded (Gzipped): {dest_key}")

        ensure_partition(partition_value)
        
        processed_count += 1

    return {
        "statusCode": 200,
        "body": json.dumps(f"Successfully processed and compressed {processed_count} files.")
    }