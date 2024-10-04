import json
import argparse
import subprocess
import tempfile
import os

def run_mine_events(address, api_token, command_type, token_or_key):
    """Run the mineEvents.py script with the specified arguments."""

    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the path to mineEvents.py
    mine_events_path = os.path.join(script_dir, 'mineEvents.py')
    
    with tempfile.NamedTemporaryFile(delete=True) as temp_file:
        command = [
            'python3', mine_events_path, address, api_token, command_type, token_or_key, temp_file.name
        ]
        
        subprocess.run(command, check=True)
        
        temp_file.seek(0)
        output = temp_file.read().decode('utf-8')
        
    return output

def main(address, api_token, token_list):
    result = {
        "http://localhost:5000/token-targets": json.dumps(
            [{"address": token} for token in token_list]
        ),
        "http://localhost:5000/pool-targets": "[]"
    }

    for token in token_list:
        url_token = "0x" + token[-40:]
        url = f"http://localhost:5000/token-pools?token={url_token}"
        

        transfer_url = f"http://localhost:5000/token-transfers?token={url_token}"
        try:
            output = run_mine_events(address, api_token, 'pools', token)
            data = json.loads(output)
            
            transfer_output = run_mine_events(address, api_token, "transfers", token)
            result[transfer_url] = transfer_output

            # Add the token pools result to the JSON
            result[url] = output

            # Process each key in the payload
            for item in data.get('payload', []):
                key = item.get('key')
                if key:
                    key_url = f"http://localhost:5000/pool-positions?key={key}"
                    
                    # Run mineEvents.py for the key
                    key_output = run_mine_events(address, api_token, 'positions', key)
                    result[key_url] = key_output
        
        except subprocess.CalledProcessError as e:
            print(f"Error while running mineEvents.py for token '{token}': {e}")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON output for token '{token}': {e}")

    # Write the final result to a JSON file
    output_filename = 'output.json'
    with open(output_filename, 'w') as json_file:
        json.dump(result, json_file, indent="  ")

    print(f"Output written to {output_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build a JSON mapping.")
    parser.add_argument("address", type=str, help="The address string.")
    parser.add_argument("api_token", type=str, help="The API token string.")
    parser.add_argument("tokenList", nargs='+', help="One or more token strings.")
    
    args = parser.parse_args()

    # Call the main function with the parsed arguments
    main(args.address, args.api_token, args.tokenList)