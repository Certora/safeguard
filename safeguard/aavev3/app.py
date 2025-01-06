from flask import Flask
from flask_cors import CORS
from typing import Optional, Dict, TypedDict
import requests
import urllib
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
target_dir = os.path.abspath(os.path.join(current_dir, '../../dashboard'))
sys.path.append(target_dir)
import dashboard_app
import time

app = Flask(__name__)
CORS(app)

class ProxyCallDict(TypedDict):
    module: str
    action: str
    to: str
    data: str
    apikey: str


spec = {
    "totalSupplyGteTotalDebt": dashboard_app.ConditionSpec(
        display_name="Total Supply ≥ Total Debt",
        details=[
            dashboard_app.ConditionDetail(
                id="atokenSupply",
                display_name="AToken Total Supply",
                fmt=dashboard_app.HexToDecimal
            ),
            dashboard_app.ConditionDetail(
                id="variableDebtSupply",
                display_name="Total Debt",
                fmt=dashboard_app.HexToDecimal
            ),
        ]
    )
}

ETHERSCAN_API_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")

def filter_rate_limited(r) -> bool:
    try:
        d = r.json()["result"]
        return "Max calls per sec rate limit reached" not in d
    except:
        return False

class AaveDashboard(dashboard_app.DashboardApp):
    def __init__(self):
        #fs_cache = requests_cache.backends.filesystem.FileCache("name_cache", use_cache_dir=True, filter_fn=filter_rate_limited)
        self.session = requests.Session()
        super().__init__(id_key="id", fmt_instructions=spec)

    def _make_etherscan_call(self, params) -> Optional[str]:
        url_params = urllib.parse.urlencode(params)
        url = f"{ETHERSCAN_API_URL}?{url_params}"
        tries = 0
        while True:
            if tries == 5:
                return None
            tries = tries + 1
            res = self.session.get(url)
            data = res.json()
            if "result" in data:
                if "Max calls per sec rate limit reached" in data["result"]:
                    time.sleep(1.0)
                    continue
                return data["result"]
            else:
                return None
            
    def _decode_abi_string(self, s: str) -> Optional[str]:
        if s[0:2] != "0x":
            return None
        raw_bytes = bytes.fromhex(s[2:])
        # abi encoding has 64 bytes of padding: 32 for the pointer, 32 for the length field
        if len(raw_bytes) < 64:
            return None
        string_data = raw_bytes[64:]
        return string_data.decode("utf-8").rstrip("\x00")

    def _get_contract_call(self, to: str, selector: str) -> ProxyCallDict:
        return {
            "module": "proxy",
            "action": "eth_call",
            "to": to,
            "data": selector,
            "apikey": ETHERSCAN_API_KEY
        }

    def format_id(self, id: str) -> str:
        # The data for the name function call (0x06fdde03 is the method signature for name())
        name_selector = "0x06fdde03"
        symbol_selector = "0x95d89b41"

        raw_name_data = self._make_etherscan_call(self._get_contract_call(id, name_selector))
        name = None
        if raw_name_data is not None:
            name = self._decode_abi_string(raw_name_data)
        
        raw_symbol_data = self._make_etherscan_call(self._get_contract_call(id, symbol_selector))
        symbol = None
        if raw_symbol_data is not None:
            symbol = self._decode_abi_string(raw_symbol_data)

        if symbol is None and name is None:
            return f"Reserve with Address {id}"
        
        if name is not None and symbol is not None:
            return f"{name} ({symbol}) Reserve"
        if name is not None:
            return f"{name} Reserve"
        return f"{symbol} Reserve"

dashboard=AaveDashboard()
dashboard.route(app)

if __name__ == '__main__':
    app.run(debug=True)