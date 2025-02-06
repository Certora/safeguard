from typing import Dict, Union, Any, List, Optional
from abc import ABC, abstractmethod
from flask import Flask, jsonify, request
from flask import abort as wrapped_abort
from enum import Enum
from dataclasses import dataclass
import os
import time
from datetime import datetime

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


class Slack:
    """
    A simple Slack client for sending alert messages.
    """
    def __init__(self, channel: str = '#aave-alert-test', slack_token: Optional[str] = None):
        if not slack_token:
            slack_token = os.environ.get('SLACK_TOKEN')
        self.client = WebClient(token=slack_token)
        self.channel = channel

    def send_message(self, message: str):
        try:
            self.client.chat_postMessage(channel=self.channel, text=message)
            print(f'Message sent: {message}')
        except SlackApiError as e:
            print(f'Error sending message: {e}')


# ---------------------------------------------------------------------
# Formatters and Models for condition details
# ---------------------------------------------------------------------

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

def abort(status_code, msg):
    wrapped_abort(status_code, msg)

class InvariantStatus:
    def __init__(self):
        self.status: Status = Status.UNKNOWN
        self.timestamp: int = 0
        self.block_number: int = 0
        self.conditions: List[Dict[str, Any]] = []
        self.err: Optional[str] = None

    def update(self, payload: Dict[str, Any]):
        if "blockNumber" not in payload or not isinstance(payload["blockNumber"], int):
            abort(400, "Missing blockNumber parameter")
        if "calculationTimestamp" not in payload or not isinstance(payload["calculationTimestamp"], int):
            abort(400, "Missing timestamp")
        if ("invariantStatus" not in payload or not isinstance(payload["invariantStatus"], str) or
            payload["invariantStatus"] not in {"error", "success", "failure"}):
            abort(400, "Missing or ill-formed invariantStatus")

        if payload["invariantStatus"] == "error":
            if "error" not in payload or not isinstance(payload["error"], str):
                abort(400, "Missing or illegal error message")
            self.timestamp = payload["calculationTimestamp"]
            self.block_number = payload["blockNumber"]
            self.status = Status.ERROR
            self.err = payload["error"]
            return

        if "conditionsChecked" not in payload or not isinstance(payload["conditionsChecked"], list):
            abort(400, "Missing or malformed conditions checked")

        self.status = Status.OK if payload["invariantStatus"] == "success" else Status.VIOLATED
        for c in payload["conditionsChecked"]:
            if not isinstance(c, dict):
                abort(400, "Malformed conditions")
            if "condition" not in c or not isinstance(c["condition"], str):
                abort(400, "Malformed condition name")
            if "status" not in c or not isinstance(c["status"], bool):
                abort(400, "Incorrect status")
            if "values" not in c or not isinstance(c["values"], dict):
                abort(400, "Missing condition values")

        self.conditions = payload["conditionsChecked"]
        self.block_number = payload["blockNumber"]
        self.timestamp = payload["calculationTimestamp"]
        self.err = None

    def getStatus(self, condition_specs: Dict[str, ConditionSpec]) -> Dict[str, Any]:
        if self.status == Status.UNKNOWN:
            return {"status": "not ready", "message": "Not loaded"}
        elif self.status == Status.ERROR:
            return {"status": "error", "message": self.err}

        result = {
            "blockNumber": self.block_number,
            "time": self.timestamp,
            "status": "success" if self.status == Status.OK else "violated",
            "info": []
        }
        for c in self.conditions:
            cond_name = c["condition"]
            if cond_name not in condition_specs:
                abort(500, f"Unknown condition name {cond_name}")
            cs = condition_specs[cond_name]
            detail_list = []
            for detail in cs.details:
                if detail.id not in c["values"]:
                    abort(500, f"Missing detail {detail.id}")
                value = c["values"][detail.id]
                if isinstance(detail.fmt, str):
                    display_value = detail.fmt % value
                else:
                    display_value = detail.fmt.format(detail.id, value)
                detail_list.append({"id": detail.id, "name": detail.display_name, "display": display_value})
            result["info"].append({
                "id": cond_name,
                "name": cs.display_name,
                "status": c["status"],
                "details": detail_list
            })
        return result

# ---------------------------------------------------------------------
# Formatter helper objects
# ---------------------------------------------------------------------

class HexToDecimalFormatter(DetailValueFormatter):
    def format(self, key: str, value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("Bad value")
        val = value[2:] if value.startswith("0x") else value
        return f"{int(val, 16):,}"

class StringToIntFormatter(DetailValueFormatter):
    def format(self, key: str, value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("Bad value")
        return f"{int(value):,}"

class IntToDecimalFormatter(DetailValueFormatter):
    def format(self, key: str, value: Any) -> str:
        if not isinstance(value, int):
            raise RuntimeError("Bad value")
        return f"{value:,}"

HexToDecimal = HexToDecimalFormatter()
IntToDecimal = IntToDecimalFormatter()
StringToInt = StringToIntFormatter()

# ---------------------------------------------------------------------
# DashboardApp with Slack alerts
# ---------------------------------------------------------------------

class DashboardApp:
    """
    Core class for building a dashboard to monitor invariant statuses.
    Each monitored target is assigned an ID and its state (OK, VIOLATED, ERROR, UNKNOWN)
    is updated via HTTP requests. This class also sends Slack alerts on state transitions.
    """
    def __init__(self, id_key: str, fmt_instructions: Dict[str, ConditionSpec]):
        self.formatters = fmt_instructions
        self.state: Dict[str, InvariantStatus] = {}
        self.register_order: List[Dict[str, str]] = []
        self.id_key = id_key
        self.slack = Slack()
        self.clean_block_count = 1000
        self.last_message_update = time.time()

    def send_slack_alert(
        self,
        alert_type: str,
        target: str,
        block_number: int,
        details: Optional[Any] = None,
        prev_status: Optional[Status] = None
    ):
        """
        Constructs and sends a Slack alert based on the alert_type.

        Parameters
        ----------
        alert_type : str
            The type of alert ("violation", "recovery", "error", or "update").
        target : str
            The monitor target's identifier.
        block_number : int
            The current block number at which the status change was detected.
        details : Optional[Any]
            Additional details to include in the message.
        prev_status : Optional[Status]
            The previous status (only used for violation alerts).
        """
        formatted_target = self.format_id(target)
        if alert_type == "violation":
            # Include previous state information if available.
            transition_info = f" (Transitioned from {prev_status.name})" if prev_status else ""
            message = (
                f"❌ *Invariant Violation Alert{transition_info}*\n"
                f"• Target: {formatted_target}\n"
                f"• Block: {block_number}\n"
                f"• Violation Details:\n```{details}```"
            )
        elif alert_type == "recovery":
            message = (
                f"✅ *Invariant Recovery Alert*\n"
                f"• Target: {formatted_target}\n"
                f"• Block: {block_number}\n"
                f"• Invariant condition has been restored."
                f"• Details: {details}"
            )
        elif alert_type == "error":
            message = (
                f"⚠️ *Invariant Error Alert*\n"
                f"• Target: {formatted_target}\n"
                f"• Block: {block_number}\n"
                f"• Error: ```{details}```"
            )
        else:
            raise ValueError(f"Invalid alert type: {alert_type}")

        self.slack.send_message(message)
        self.last_message_update = time.time()

    def handle_status_change(
        self,
        target: str,
        old_status: Status,
        new_status: Status,
        block_number: int,
        payload: Dict[str, Any]
    ):
        """
        Determines which type of Slack alert to send based on status transition.

        Parameters
        ----------
        target : str
            The monitor target's identifier.
        old_status : Status
            The previous status.
        new_status : Status
            The new status.
        block_number : int
            The block number from the payload.
        payload : Dict[str, Any]
            The raw update payload.
        """
        # Transition into a violation state from a non-violation state.
        if new_status == Status.VIOLATED and old_status in {Status.OK, Status.UNKNOWN, Status.ERROR}:
            self.send_slack_alert("violation", target, block_number, details=payload, prev_status=old_status)
        # Transition into a healthy state from a violation state.
        elif new_status == Status.OK and old_status == Status.VIOLATED:
            self.send_slack_alert("recovery", target, block_number, details=payload)
        # In case of error status.
        elif new_status == Status.ERROR:
            self.send_slack_alert("error", target, block_number, details=payload)

    def format_id(self, id: str) -> str:
        """
        Formats the monitor target's ID. By default, returns the raw id.
        """
        return id

    def check_no_new_violations(self, block_number: int):
        now = time.time()
        if now - self.last_message_update >= 3600:
            hour_start = datetime.fromtimestamp(self.last_message_update)
            hour_end = datetime.fromtimestamp(now)
            msg = (
                f"ℹ️ *No Invariant Violations Detected*\n"
                f"From {hour_start.strftime('%H:%M')} to {hour_end.strftime('%H:%M')}, no new violations were recorded.\n"
                f"Last checked block: {block_number}"
            )
            self.slack.send_message(msg)
            self.last_message_update = now

    def route(self, app: Flask):
        @app.route("/update", methods=["POST"])
        def update():
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
            data = request.get_json()
            if self.id_key not in data:
                return jsonify({"error": "Missing id parameter"}), 400

            target_id = data[self.id_key]
            if target_id not in self.state:
                self.state[target_id] = InvariantStatus()
                try:
                    name = self.format_id(target_id)
                except Exception:
                    name = target_id
                self.register_order.append({"id": target_id, "name": name})

            old_status = self.state[target_id].status
            self.state[target_id].update(data)
            new_status = self.state[target_id].status
            self.handle_status_change(target_id, old_status, new_status, self.state[target_id].block_number, data)
            self.check_no_new_violations(self.state[target_id].block_number)
            return jsonify({"status": "accepted"}), 200

        @app.route("/targets", methods=["GET"])
        def targets():
            return jsonify(self.register_order), 200

        @app.route("/status/<string:id>", methods=["GET"])
        def status(id):
            if id not in self.state:
                return jsonify({"status": "not found"}), 400
            return jsonify(self.state[id].getStatus(self.formatters)), 200
