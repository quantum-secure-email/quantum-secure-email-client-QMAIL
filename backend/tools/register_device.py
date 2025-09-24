#!/usr/bin/env python3
# tools/register_device.py
import json, sys, requests, argparse, base64
from pathlib import Path

SERVER = "http://localhost:8000"
LOCAL_MAP = Path("tools/device_registry_local.json")

def load_map():
    if LOCAL_MAP.exists():
        return json.loads(LOCAL_MAP.read_text())
    return {}

def save_map(m):
    LOCAL_MAP.parent.mkdir(parents=True, exist_ok=True)
    LOCAL_MAP.write_text(json.dumps(m, indent=2))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pubfile", help="Path to file containing pub_b64 (or pass --pubb64 directly)")
    p.add_argument("--pubb64", help="Public key base64")
    p.add_argument("--name", help="device name metadata", default="local-laptop")
    args = p.parse_args()

    if args.pubb64:
        pub_b64 = args.pubb64
    elif args.pubfile:
        pub_b64 = Path(args.pubfile).read_text().strip()
    else:
        print("Provide --pubfile or --pubb64")
        sys.exit(1)

    payload = {"pubkey_b64": pub_b64, "meta": {"name": args.name}}
    r = requests.post(f"{SERVER}/device/register", json=payload)
    r.raise_for_status()
    resp = r.json()
    did = resp.get("device_id")
    if not did:
        print("registration response:", resp)
        sys.exit(1)

    mapping = load_map()
    mapping[did] = {"pubkey_b64": pub_b64, "meta": {"name": args.name}}
    save_map(mapping)

    print("Registered device_id:", did)
    print("Server status:", resp.get("status"))
    print("Local mapping saved to tools/device_registry_local.json")

if __name__ == "__main__":
    main()
