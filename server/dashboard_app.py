from typing import Dict, Union, Any, List, Optional
from abc import ABC, abstractmethod
from flask import Flask, jsonify, request
from flask import abort as wrapped_abort
from enum import Enum
from dataclasses import dataclass

class DetailValueFormatter(ABC):
    @abstractmethod
    def format(self, key: str, value: Any) -> str:
        pass

@dataclass
class ConditionDetail:
    id: str
    display_name: str
    fmt: Union[str, DetailValueFormatter]

@dataclass
class ConditionSpec:
    display_name: str
    details: List[ConditionDetail]

class Status(Enum):
    UNKNOWN = 1
    ERROR = 2
    VIOLATED = 3
    OK = 4

def abort(s, msg):
    print(f"Aborting with {s} because {msg}")
    wrapped_abort(s, msg)

class InvariantStatus(object):
    def __init__(self):
        self.status = Status.UNKNOWN
        self.timestamp = 0
        self.block_number = 0
        self.conditions = {} #type: List[Dict[str,Any]]
        self.err = None #type: Optional[str]
        pass

    def update(self, payload: Dict[str,Any]):
        if "blockNumber" not in payload or type(payload["blockNumber"]) != int:
            abort(400, "Missing blockNumber parameter")
        if "calculationTimestamp" not in payload or type(payload["calculationTimestamp"]) != int:
            abort(400, "missing timestamp")
        if "invariantStatus" not in payload or type(payload["invariantStatus"]) != str or payload["invariantStatus"] not in {"error", "success", "failure"}:
            abort(400, "missing or ill-formed invariantStatus")
        
        if payload["invariantStatus"] == "error":
            if "error" not in payload or type(payload["error"]) != str:
                abort(400, "missing or illegal error message")
            self.timestamp = payload["calculationTimestamp"]
            self.block_number = payload["blockNumber"]
            self.status = Status.ERROR
            self.err = payload["error"]
            return
    
        if "conditionsChecked" not in payload or type(payload["conditionsChecked"]) != list:
            abort(400, "missing or mal-formed conditions checked")
        
        if payload["invariantStatus"] == "success":
            stat = Status.OK
        else:
            stat = Status.VIOLATED
        
        # now validate the conditions checked
        conds = payload["conditionsChecked"]
        for c in conds:
            if type(c) != dict:
                abort(400, "malformed conditions")
            
            if "condition" not in c or type(c["condition"]) != str:
                abort(400, "malformed condition name")
            if "status" not in c or type(c["status"]) != bool:
                abort(400, "incorrect status")
            if "values" not in c or type(c["values"]) != dict:
                abort(400, "missing condition values")

        self.status = stat
        self.conditions = conds
        self.block_number = payload["blockNumber"]
        self.timestamp = payload["calculationTimestamp"]
        self.err = None
    
    def getStatus(self, condition: Dict[str, ConditionSpec]) -> Dict[str,Any]:
        msg = {}
        if self.status == Status.UNKNOWN:
            return {"status": "not ready", "message": "Not loaded"}
        elif self.status == Status.ERROR:
            return {"status": "error", "message": self.err}
        else:
            msg = {
                "blockNumber": self.block_number,
                "time": self.timestamp,
                "status": "success" if self.status == Status.OK else "violated"
            }
            msg["info"] = []
            for c in self.conditions:
                condName = c["condition"]
                condition_result = {
                    "id": condName,
                    "status": c["status"]
                }
                if condName not in condition:
                    abort(500, f"Unknown condition name {condName}")
                cs = condition[condName]
                condition_result["name"] = cs.display_name
                condition_result["details"] = []
                for detail in cs.details:
                    if detail.id not in c["values"]:
                        abort(500, f"missing detail {detail.id}")
                    detail_value = c["values"][detail.id]
                    detail_dict = {"id": detail.id, "name": detail.display_name}
                    if type(detail.fmt) == str:
                        detail_display = detail.fmt % (detail_value)
                    else:
                        detail_display = detail.fmt.format(detail.id, detail_value)
                    detail_dict["display"] = detail_display
                    condition_result["details"].append(detail_dict)
                msg["info"].append(condition_result)
            return msg


class HexToDecimalFormatter(DetailValueFormatter):
    def format(self, key, value) -> str:
        if type(value) != str:
            raise RuntimeError("Bad value")
        if value.startswith("0x"):
            value = value[2:]
        decimal = int(value, 16)
        return f"{decimal:,}"
    
HexToDecimal = HexToDecimalFormatter()
    
class IntToDecimalFormatter(DetailValueFormatter):
    def format(self, key, value) -> str:
        if type(value) != int:
            raise RuntimeError("Bad value")
        return f"{value:,}"
        

IntToDecimal = IntToDecimalFormatter()

class DashboardApp:
    def on_violation(self, id: str, violation: Dict[str, Any]):
        pass

    def format_id(self, id: str) -> str:
        return id

    def __init__(self, id_key: str, fmt_instructions: Dict[str, ConditionSpec]):
        self.formatters = fmt_instructions
        self.state = {} #type:Dict[str,InvariantStatus]
        self.register_order = [] #type:List[Dict[str,str]]
        self.id_key = id_key

    def route(self, app: Flask):
        @app.route("/update", methods=["POST"])
        def update():
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
            data = request.get_json()
            if self.id_key not in data:
                return jsonify({"error": "missing id"}), 400
            id = data[self.id_key]
            if id not in self.state:
                self.state[id] = InvariantStatus()
                try:
                    name = self.format_id(id)
                except:
                    name = id
                self.register_order.append({"id": id, "name": name})
            old_state = self.state[id].status
            self.state[id].update(data)
            if self.state[id].status == Status.VIOLATED and old_state != Status.VIOLATED:
                self.on_violation(id, data)
            
            return jsonify({"status": "accepted"}), 200
        
        @app.route("/targets", methods=["GET"])
        def target():
            return jsonify(self.register_order), 200
        
        @app.route("/status/<string:id>", methods=["GET"])
        def status(id):
            if id not in self.state:
                return jsonify({"status": "not found"}), 400
            return self.state[id].getStatus(self.formatters), 200
        
