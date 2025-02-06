from typing import Dict, Union, Any, List, Optional
from abc import ABC, abstractmethod
from flask import Flask, jsonify, request
from flask import abort as wrapped_abort
from enum import Enum
from dataclasses import dataclass

import os
from typing import Optional
import time
from datetime import datetime, timedelta

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


class Slack:
    '''
    Description
    -----------
    This class is used to send messages with runs summaries to a Slack channel.
    '''
    def __init__(self, channel: str = '#aave-alert-test', slack_token: Optional[str] = None):
        '''
        Summary
        -------
        Initializes a new instance of the Slack class.

        Parameters
        ----------
        channel : str, default = '#aave-alert-test'
            The name of the Slack channel to send messages to.
        slack_token : Optional[str], default = None
            The Slack API token to use for authentication. If not provided, it will be loaded from the 'SLACK_TOKEN' environment variable.
        '''
        if not slack_token:
            slack_token = os.environ.get('SLACK_TOKEN')
        
        self.client = WebClient(token=slack_token)
        self.channel = channel

    def send_message(self, message: str):
        '''
        Summary
        -------
        Sends a message to the Slack channel.

        Parameters
        ----------
        message : str
            The message to send.
        '''
        try:
            self.client.chat_postMessage(channel=self.channel, text=message)
            print(f'Message sent: {message}')
        except SlackApiError as e:
            print(f'Error sending message: {e}')

"""
This module contains some common code for building a dashboard for invariant monitoring.

This can be used for a production dashboard, but is primarily meant for debugging.

The core piece is DashboardApp, which can be extended to receive update messages posted by the
safeguard node and serve status results to the dashboard page (the html for which is included here).
"""

class DetailValueFormatter(ABC):
    """
    Basic class used to format the values in a condition detail.
    """
    @abstractmethod
    def format(self, key: str, value: Any) -> str:
        """
        Given a key and value, return a pretty-printed representation of the value.
        """
        pass

@dataclass
class ConditionDetail:
    """
    Describes a detail in a condition. id is the key in the details dictionary, display_name is the human readable name of detail,
    and fmt is either a DetailValueFormatter, or a format string (using %s etc.)
    """
    id: str
    display_name: str
    fmt: Union[str, DetailValueFormatter]

@dataclass
class ConditionSpec:
    """
    Describes one of the conditions checked as part of an overall invariant. display_name is the human readable desciption of the condition,
    and details is a list of ConditionDetail objects which describe how to format the details of the condition.
    """
    display_name: str
    details: List[ConditionDetail]

class Status(Enum):
    UNKNOWN = 1
    ERROR = 2
    VIOLATED = 3
    OK = 4

def abort(s, msg):
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

class StringToIntFormatter(DetailValueFormatter):
    def format(self, key, value) -> str:
        if type(value) != str:
            raise RuntimeError("Bad value")
        decimal = int(value)
        return f"{decimal:,}"

"""
Helper object to format a hexadecimal string into a decimal string representation with digit separators.
"""
HexToDecimal = HexToDecimalFormatter()
    
class IntToDecimalFormatter(DetailValueFormatter):
    def format(self, key, value) -> str:
        if type(value) != int:
            raise RuntimeError("Bad value")
        return f"{value:,}"
        

"""
Helper object to for a json number into a decimal string with digit separators
"""
IntToDecimal = IntToDecimalFormatter()


"""
Helper object to format a string into a string representation with digit separators.
"""
StringToInt = StringToIntFormatter()

class DashboardApp:
    """
    Basic class for building a dashboard. Associates unique ids to the status of the invariant
    result for that id. The actual ID chosen can be anything. We will call the "thing" associated
    with an id (the thing being monitored) the "monitor target."

    The status of monitor targets are communicated with invariant status messages, the format of these
    messages is described in Message.md
    """

    def on_violation(self, id: str, violation: Dict[str, Any]):
        """
        Called on the first violation observed for a "monitor target". More precisely, if the status of a monitor
        goes from any that is not VIOLATED to VIOLATED, this function is called. Thus, if a monitor results
        goes from good -> bad -> good -> bad this function will be called twice.

        id is the id of the monitor target, and violate is the raw payload sent by the server.
        """
        self.last_message_update = time.time()
        # Send a message to slack when a violation is detected for a monitor target
        self.slack.send_message(f"New invariant violation detected for {self.format_id(id)}")
        self.slack.send_message(f"Details: {violation}")

    def format_id(self, id: str) -> str:
        """
        Formats the monitor target's ID into something more descriptive (e.g., pool address to pool name). By
        default uses the monitor target's id.
        """
        return id

    def __init__(self, id_key: str, fmt_instructions: Dict[str, ConditionSpec]):
        """
        id_key is the key in the top-level envelope holds the monitor target's id
        fmt_instructions maps the condition ids that appear in the invariant envelope's condition
        to the instructions on how to format the condition using the ConditionSpec
        """
        self.formatters = fmt_instructions
        self.state = {} #type:Dict[str,InvariantStatus]
        self.register_order = [] #type:List[Dict[str,str]]
        self.id_key = id_key
        self.slack = Slack()
        self.clean_block_count = 1000
        self.last_message_update = time.time()

    def check_no_violations(self, block_number: int):
        now = time.time()
        if now - self.last_message_update >= 3600:
            hour_start = datetime.fromtimestamp(self.last_message_update)
            hour_end = datetime.fromtimestamp(now)
            msg = f"From {hour_start.strftime('%H:%M')} to {hour_end.strftime('%H:%M')} no new violations were recorded.\n"
            msg += f"Last checked block number: {block_number}"
            self.slack.send_message(msg)
            self.last_message_update = now

    def route(self, app: Flask):
        """
        Sets up three end points on app.
        `/update`, which receives POST requests holding the invariant status messages and updates this dashboards internal state;
        `/targets` which receives GET requests and returns a list of all monitor target ids for which this dashboard has data
        `/status/<string:id>` which receives a GET request whith the URL parameter id, and returns the status of the invariant in a format
        to be rendered on dashboard.html
        """
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
            self.check_no_violations(self.state[id].block_number)
            
            return jsonify({"status": "accepted"}), 200
        
        @app.route("/targets", methods=["GET"])
        def target():
            return jsonify(self.register_order), 200
        
        @app.route("/status/<string:id>", methods=["GET"])
        def status(id):
            if id not in self.state:
                return jsonify({"status": "not found"}), 400
            return self.state[id].getStatus(self.formatters), 200

