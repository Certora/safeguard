import json
import urllib.request
import sys
import os
import hashlib
import time
import sha3
import argparse

query_template = "https://api-sepolia.etherscan.io/api?module=logs&action=getLogs&address=%s&page=%d&offset=1000&apikey=%s&topic0=%s"

cps = 5.0

def extract_position_from_mint(obj):
    topics = obj["topics"]
    owner = topics[1]
    tickLow = topics[2]
    tickHigh = topics[3]
    return (owner, tickLow, tickHigh)


def extract_position_from_burn(obj):
    topics = obj["topics"]
    owner = topics[1]
    tickLow = topics[2]
    tickHigh = topics[3]
    return (owner, tickLow, tickHigh)

def extract_position_hash(keys):
    data = b''.join([bytes.fromhex(keys[0][-40:]), bytes.fromhex(keys[1][-6:]), bytes.fromhex(keys[2][-6:]), bytes.fromhex(keys[3])])
    kec = sha3.keccak_256()
    kec.update(data)
    return kec.hexdigest()

modify_topic = "0xf208f4912782fd25c7f114ca3723a2d5dd6f3bcc3ac8db5af63baa85f711d5ec"
initialize_topic = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
transfer_topic = "0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859"

throttle_limit = 1.0 / cps
throttle_limit += throttle_limit / 2

def parse_logs(args, topic, cb, **extra_topics):
    max_block = 0
    time_query_url = "https://api-sepolia.etherscan.io/api?module=block&action=getblocknobytime&closest=before&apikey=%s&timestamp=%d" % (args.apikey, int(time.time()))
    with urllib.request.urlopen(time_query_url) as response:
        if response.status != 200:
            max_block = 0
        else:
            block_res = json.loads(response.read().decode("utf-8"))
            if "result" in block_res and type(block_res["result"]) is str:
                max_block = int(block_res["result"])
    time.sleep(throttle_limit)
    page_counter = 1
    block_start = None
    while True:
        query_url = query_template % (args.address, page_counter, args.apikey, topic)
        for (id, et) in extra_topics.items():
            query_url += f"&{id}={et}"
        if block_start is not None:
            query_url += "&fromBlock=%d" % block_start
        cache_key = "cache_" + hashlib.md5(query_url.encode('utf-8')).hexdigest()
        print("querying %s" % query_url)
        if os.path.isfile(cache_key):
            print("File system cache hit")
            with open(cache_key, 'r') as f:
                contents = f.read()
        else:
            print("going to ethscan system")
            with urllib.request.urlopen(query_url) as response:
                if response.status != 200:
                    raise RuntimeError("welp")
                contents = response.read().decode('utf-8')
        obj = json.loads(contents)
        if obj["message"] != "OK":
            if obj["message"] == "No records found":
                break
            raise RuntimeError(f"failed querying {query_url}, result was: {contents}")
        for i in obj["result"]:
            cb(i)
        max_block = max(max_block, int(obj["result"][-1]["blockNumber"], 16))
        if len(obj["result"]) != 1000:
            break
        with open(cache_key, 'w') as f:
            f.write(contents)
        page_counter += 1
        if page_counter > 10:
            block_start = int(obj["result"][-1]["blockNumber"], 16)
            page_counter = 1
        time.sleep(throttle_limit)
    return max_block

def extract_int24(hex_string):
    num = int(hex_string, 16)
    if num >= 2 ** 23:
        num -= 2**24
    return num

def scan_positions(args):
    position_to_ticks = dict()
    def parse_position(log_item):
        sender = log_item["topics"][2]
        tick_lower_raw = log_item["data"][2:66]
        tick_lower = extract_int24(tick_lower_raw[-6:])
        tick_upper_raw = log_item["data"][66:130]
        tick_upper = extract_int24(tick_upper_raw[-6:])
        salt = log_item["data"][-64:]
        computed_hash = extract_position_hash((sender, tick_lower_raw, tick_upper_raw, salt))
        position_to_ticks[computed_hash] = { "tickLower": tick_lower, "tickUpper": tick_upper, "positionHash": computed_hash }
    max_block = parse_logs(args, modify_topic, parse_position, topic1=args.mode_arg)
    payload = list(position_to_ticks.values())
    output = {
        "done": True,
        "lastBlock": max_block,
        "payload": payload
    }
    with open(args.output, 'w') as f:
        f.write(json.dumps(output, indent = "  "))

def scan_transfers(args):
    address_list = set()
    def parse_transfer(log_item):
        to = log_item["topics"][2]
        address_list.add(to)
    max_block = parse_logs(args, transfer_topic, parse_transfer, topic3=args.mode_arg)
    payload = list(address_list)
    output = {
        "done": True,
        "lastBlock": max_block,
        "payload": payload
    }
    with open(args.output, 'w') as f:
        f.write(json.dumps(output, indent = "  "))

def scan_pools(args):
    to_ret = []
    def parse_pool_info(log_data):
        to_ret.append({
            "key": log_data["topics"][1],
            "currency0": log_data["topics"][2],
            "currency1": log_data["topics"][3],
            "hooks": "0x" + log_data["data"][66:66+32],
            "tickSpacing": extract_int24(log_data["data"][66-6:66]),
            "fee": int(log_data["data"][34-6:34], 16)
        })

    token_addr = args.mode_arg
    max_block = parse_logs(args, initialize_topic, parse_pool_info, topic2=token_addr)
    mb2 = parse_logs(args, initialize_topic, parse_pool_info, topic3=token_addr)
    max_block = max(max_block, mb2)
    output = {
        "done": True,
        "lastBlock": max_block,
        "payload": to_ret
    }
    with open(args.output, 'w') as f:
        f.write(json.dumps(output, indent="  "))
    

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Fetch logs from Etherscan API")
    parser.add_argument("address", type=str, help="The contract address to query")
    parser.add_argument("apikey", type=str, help="Your Etherscan API key")
    parser.add_argument("mode", type=str, help="The scan type")
    parser.add_argument("mode_arg", type=str, help="Argument for the scan")
    parser.add_argument("output", type=str, help="output file")
    parser.add_argument("--requests_per_second", type=float, default=5.0, 
                        help="Maximum number of requests per second (default: 5)")

    args = parser.parse_args()

    global throttle_limit
    throttle_limit = 1.0 / args.requests_per_second
    throttle_limit += throttle_limit / 2.0

    if args.mode == "pools":
        scan_pools(args)
    elif args.mode == "positions":
        scan_positions(args)
    elif args.mode == "transfers":
        scan_transfers(args)
    else:
        print(f"Unknown mode{args.mode}")
        sys.exit(1)
    
if __name__ == "__main__":
    main()