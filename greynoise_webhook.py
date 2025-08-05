# File: greynoise_webhook.py
#
# Copyright (c) GreyNoise, 2019-2025
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
"""
GreyNoise Webhook Handler for SOAR Platform.

This module handles incoming webhooks from GreyNoise's integration,
processes the alert data, and creates SOAR containers and artifacts.
The module is structured in a modular way with separate functions for
each responsibility, following clean code principles.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional, Union

from phantom_common.install_info import get_verify_ssl_setting


# Constants
CONTENT_TYPE_HEADER = ["Content-Type", "application/json"]
LABEL_EVENTS = "events"
GREYNOISE_FEED_IP_EVENT_TYPE = "ip-classification-change"
GREYNOISE_FEED_CVE_EVENT_TYPE = "cve-status-change"
GREYNOISE_ALERT_TAG = "greynoise-alert"
GREYNOISE_FEED_TAG = "greynoise-feed"
GREYNOISE_FEED_CVE_TAG = "greynoise-feed-cve"
GREYNOISE_FEED_IP_TAG = "greynoise-feed-ip"

# Response status codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_METHOD_NOT_ALLOWED = 405

# Classification severity mapping
SEVERITY_MAP = {"malicious": "high", "suspicious": "medium", "benign": "low"}

# Default severity when classification is not recognized
DEFAULT_SEVERITY = "medium"

logger = logging.getLogger("app_interface")


def create_error_response(status_code: int, error: str, message: str) -> dict[str, Any]:
    """
    Create a standardized error response.

    Args:
        status_code: HTTP status code
        error: Short error description
        message: Detailed error message

    Returns:
        A dictionary with the response status code, headers and content
    """
    return {"status_code": status_code, "headers": [CONTENT_TYPE_HEADER], "content": json.dumps({"error": error, "message": message})}


def validate_request(method: str, body: str) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """
    Validate the incoming webhook request method and body.

    Args:
        method: HTTP method used in the request
        body: Request body as a string

    Returns:
        Tuple containing (parsed JSON data, error response or None)
    """
    # Validate request method
    if method.lower() != "post":
        return None, create_error_response(HTTP_OK, "Method not allowed", "Only POST requests are supported")

    # Parse and validate the incoming JSON data
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None, create_error_response(HTTP_BAD_REQUEST, "Invalid JSON", "Request body contains invalid JSON")

    # Validate expected data format
    if not data:
        return None, create_error_response(HTTP_BAD_REQUEST, "Empty data", "Request body contains empty JSON data")

    return data, None


def format_utc_timestamp(iso_timestamp: str, mode: str = "datetime") -> str:
    """
    Format an ISO 8601 UTC timestamp based on mode.

    Args:
        iso_timestamp (str): Timestamp in 'YYYY-MM-DDTHH:MM:SS.mmmmmmZ' or 'YYYY-MM-DDTHH:MM:SSZ' format.
        mode (str): 'datetime' for full timestamp, 'date' for date only.

    Returns:
        str: Formatted timestamp string based on the mode.
    """
    try:
        if "." in iso_timestamp:
            # Handle timestamp received from GreyNoise CVE feed
            if len(iso_timestamp.split(".")[1]) > 6:
                # trim the microseconds to 6 digits
                iso_timestamp = iso_timestamp[: iso_timestamp.index(".") + 7] + "Z"
            dt = datetime.strptime(iso_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            dt = datetime.strptime(iso_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        if mode == "date":
            return dt.strftime("%Y-%m-%d (UTC)")
        elif mode == "datetime":
            return dt.strftime("%Y-%m-%d %H:%M:%S (UTC)")
        else:
            raise ValueError(f"Unsupported mode: {mode}")
    except ValueError as e:
        return f"Error: {e!s}"


def determine_severity(classification: str) -> str:
    """
    Determine the severity level based on classification.

    Args:
        classification: The classification string from the alert

    Returns:
        A severity string (high, medium, or low)
    """
    return SEVERITY_MAP.get(classification.lower(), DEFAULT_SEVERITY)


def convert_to_cef_fields(data: dict[str, Any]) -> dict[str, Any]:
    """
    Convert the feed data to CEF fields.

    Args:
        data: The data to convert

    Returns:
        A dictionary containing the CEF fields
    """
    cef_fields = {k.split("_")[0] + "".join(word.capitalize() for word in k.split("_")[1:]): v for k, v in data.items()}
    return cef_fields


def create_alert_container(alert_metadata: dict[str, Any], alert_timestamp: str, soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save a container object in the SOAR platform.

    Args:
        alert_metadata: Alert metadata from the alert
        alert_timestamp: Timestamp of the alert
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        The ID of the created container

    Raises:
        Exception: If container creation fails
    """
    # Generate container data

    alert_name = alert_metadata.get("name")
    alert_id = alert_metadata.get("id")
    alert_type = alert_metadata.get("type").upper()
    formatted_timestamp = format_utc_timestamp(alert_timestamp)

    container = {
        "name": f"GreyNoise Alert: {alert_name}: {alert_type}: {formatted_timestamp}",
        "source_data_identifier": str(uuid.uuid4()),
        "description": "Alert received via GreyNoise Webhook",
        "label": container_label,
        "tags": [GREYNOISE_ALERT_TAG],
    }

    # Send API request to create container
    response = soar_rest_client.session.post(
        f"{soar_rest_client.base_url}/container",
        json=container,
        verify=get_verify_ssl_setting(),
    )
    logger.warning(response.json())

    # Handle the response
    response.raise_for_status()
    container_id = response.json().get("id")

    return container_id


def create_alert_artifacts(
    container_id: int, alert_metadata: dict[str, Any], alert_ip_data: str, soar_rest_client: Any, container_label: str
) -> int:
    """
    Create and save an artifacts on the SOAR platform.

    Args:
        container_id: ID of the parent container
        alert_metadata: Alert metadata from the alert
        alert_ip_data: IP address from the alert
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        The ID of the created artifacts

    Raises:
        Exception: If artifact creation fails
    """

    artifact_ids = []
    for ip_data in alert_ip_data:
        artifact = {
            "name": f"IP Artifact: {ip_data.get('ip')}",
            "label": container_label,
            "severity": determine_severity(ip_data.get("classification")),
            "container_id": container_id,
            "run_automation": True,
            "cef": {
                "alert": convert_to_cef_fields(alert_metadata),
                "ip": ip_data.get("ip"),
                "classification": ip_data.get("classification"),
                "sourceAddress": ip_data.get("ip"),
            },
            "cef_types": {
                "ip": ["ip"],
                "sourceAddress": ["ip"],
            },
            "tags": [GREYNOISE_ALERT_TAG],
        }

        # Send API request to create artifact
        response_artifact = soar_rest_client.session.post(
            f"{soar_rest_client.base_url}/artifact",
            json=artifact,
            verify=get_verify_ssl_setting(),
        )

        # Handle the response
        if response_artifact.status_code != HTTP_OK:
            raise Exception(f"Failed to create artifact: {response_artifact.json()}")
        artifact_id = response_artifact.json().get("id")
        artifact_ids.append(artifact_id)
    return artifact_ids


def process_alert(alert: dict[str, Any], soar_rest_client: Any, container_label: str) -> tuple[int, int]:
    """
    Process a single alert from the webhook data.

    Args:
        alert: The alert data to process
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        Tuple containing (container_id, artifact_id)

    Raises:
        Exception: If there's an error creating containers or artifacts
    """
    # Extract critical fields
    alert_timestamp = alert.get("timestamp")
    alert_metadata = alert.get("alert")
    alert_ip_data = alert.get("data")
    alert_metadata.update({"viz_link": alert.get("viz_link"), "query_link": alert.get("query_link"), "alert_link": alert.get("alert_link")})

    # Create container and get container ID
    container_id = create_alert_container(alert_metadata, alert_timestamp, soar_rest_client, container_label)

    # Create artifact and get artifact ID
    artifact_ids = create_alert_artifacts(container_id, alert_metadata, alert_ip_data, soar_rest_client, container_label)

    return container_id, artifact_ids


def process_feed(feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> tuple[int, int]:
    """
    Process a single feed from the webhook data.

    Args:
        feed: The feed data to process
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        Tuple containing (container_id, artifact_id)

    Raises:
        Exception: If there's an error creating containers or artifacts
    """
    # Extract critical fields
    feed_event_type = feed.get("event_type")
    feed_timestamp = feed.get("timestamp")
    container_id = create_feed_container(feed_timestamp, soar_rest_client, container_label)

    if feed_event_type == GREYNOISE_FEED_IP_EVENT_TYPE:
        artifact_id = create_feed_ip_artifact(container_id, feed, soar_rest_client, container_label)
    elif feed_event_type == GREYNOISE_FEED_CVE_EVENT_TYPE:
        artifact_id = create_feed_cve_artifact(container_id, feed, soar_rest_client, container_label)

    return container_id, artifact_id


def convert_activity_state(state_data):
    """Convert boolean activity_seen to human-readable format"""
    return "Recent activity" if state_data.get("activity_seen", False) else "No recent activity"


def create_feed_container(feed_timestamp: str, soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save a container object in the SOAR platform.

    Args:
        feed_timestamp: Timestamp of the feed
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        The ID of the created container

    Raises:
        Exception: If container creation fails
    """
    # Generate container data
    # Extract the date from the timestamp
    date = format_utc_timestamp(feed_timestamp, mode="date")
    logger.info(f"Creating container for GreyNoise feed: {date}")
    container_name = f"GreyNoise Feed: {date}"

    # Get existing containers for the date
    response = soar_rest_client.session.get(
        f"{soar_rest_client.base_url}/container",
        params={"_filter_name": f'"{container_name}"', "_filter_label": f'"{container_label}"'},
        verify=get_verify_ssl_setting(),
    )
    response.raise_for_status()

    if response.json().get("count") > 0:
        # Container with same name exists in provided label
        return response.json().get("data")[-1].get("id")  # Return the last container ID, which will be the most recent

    # Create a new container if none exists for the date
    container = {
        "name": container_name,
        "source_data_identifier": str(uuid.uuid4()),
        "description": "Feed received via GreyNoise Webhook",
        "label": container_label,
        "tags": [GREYNOISE_FEED_TAG],
    }
    response = soar_rest_client.session.post(
        f"{soar_rest_client.base_url}/container",
        json=container,
        verify=get_verify_ssl_setting(),
    )
    response.raise_for_status()
    container_id = response.json().get("id")
    return container_id


def create_feed_ip_artifact(container_id: int, feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save an artifact on the SOAR platform.

    Args:
        container_id: ID of the container
        ip: IP address from the feed
        old_classification: Old classification of the IP
        new_classification: New classification of the IP
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        The ID of the created artifact

    Raises:
        Exception: If artifact creation fails
    """
    formatted_timestamp = format_utc_timestamp(feed.get("timestamp"))

    artifact = {
        "name": f"IP Artifact: {feed.get('ip')}",
        "label": container_label,
        "severity": determine_severity(feed.get("new_state")),
        "container_id": container_id,
        "run_automation": True,
        "cef": {
            "ip": feed.get("ip"),
            "oldClassification": feed.get("old_state"),
            "newClassification": feed.get("new_state"),
            "sourceAddress": feed.get("ip"),
            "timestamp": formatted_timestamp,
        },
        "cef_types": {
            "ip": ["ip"],
            "sourceAddress": ["ip"],
        },
        "tags": [GREYNOISE_FEED_TAG, GREYNOISE_FEED_IP_TAG],
    }
    response = soar_rest_client.session.post(
        f"{soar_rest_client.base_url}/artifact",
        json=artifact,
        verify=get_verify_ssl_setting(),
    )
    response.raise_for_status()
    artifact_id = response.json().get("id")
    return artifact_id


def create_feed_cve_artifact(container_id: int, feed: dict[str, Any], soar_rest_client: Any, container_label: str) -> int:
    """
    Create and save an artifact on the SOAR platform.

    Args:
        container_id: ID of the container
        cve: CVE from the feed
        old_state: Old state of the CVE
        new_state: New state of the CVE
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        The ID of the created artifact

    Raises:
        Exception: If artifact creation fails
    """
    formatted_timestamp = format_utc_timestamp(feed.get("timestamp"))

    artifact = {
        "name": f"CVE Artifact: {feed.get('cve')}",
        "label": container_label,
        "container_id": container_id,
        "run_automation": True,
        "cef": {
            "cve": feed.get("cve"),
            "oldState": convert_activity_state(feed.get("old_state")),
            "newState": convert_activity_state(feed.get("new_state")),
            "timestamp": formatted_timestamp,
            "oldCveStats": convert_to_cef_fields(
                {k: v for k, v in feed.get("old_state", {}).items() if k != "activity_seen"}
            ),  # Remove activity_seen from old_state since is already added in oldState
            "newCveStats": convert_to_cef_fields(
                {k: v for k, v in feed.get("new_state", {}).items() if k != "activity_seen"}
            ),  # Remove activity_seen from new_state since is already added in newState
        },
        "cef_types": {
            "cve": ["cve"],
        },
        "tags": [GREYNOISE_FEED_TAG, GREYNOISE_FEED_CVE_TAG],
    }
    response = soar_rest_client.session.post(
        f"{soar_rest_client.base_url}/artifact",
        json=artifact,
        verify=get_verify_ssl_setting(),
    )
    response.raise_for_status()
    artifact_id = response.json().get("id")
    return artifact_id


def create_success_response(container_ids: list[int], artifact_ids: list[int]) -> dict[str, Any]:
    """
    Create a success response for the webhook.

    Args:
        container_ids: List of IDs of all created containers
        artifact_ids: List of IDs of all created artifacts

    Returns:
        A dictionary with the response status code, headers and content
    """
    return {
        "status_code": HTTP_OK,
        "headers": [CONTENT_TYPE_HEADER],
        "content": json.dumps(
            {
                "container_ids": container_ids,
                "artifact_ids": artifact_ids,
            }
        ),
    }


def handle_webhook(
    method: str,
    headers: dict[str, str],
    path_parts: list[str],
    query: dict[str, Union[str, list[str]]],
    body: str,
    asset: dict[str, Any],
    soar_rest_client: Any,
) -> dict[str, Any]:
    """
    Handle incoming webhooks from GreyNoise.

    This function processes incoming data from GreyNoise's webhook integration,
    creates containers and artifacts based on the data, and returns an appropriate response.

    Args:
        method: HTTP method used in the request (e.g., 'POST', 'GET')
        headers: HTTP headers from the request
        path_parts: Components of the URL path
        query: URL query parameters
        body: Request body as a string
        asset: Asset configuration information
        soar_rest_client: Client for interacting with SOAR platform

    Returns:
        A dictionary with the response status code and content
    """
    logger.info(f"Received method: {method}")
    logger.info(f"Received headers: {headers}")
    logger.info(f"Received path_parts: {path_parts}")
    logger.info(f"Received query: {query}")
    logger.info(f"Received body: {body}")
    logger.info(f"Received asset: {asset}")

    container_label = asset.get("ingest", {}).get("container_label", "events")
    # Validate request
    validated_data, error_response = validate_request(method, body)
    if error_response:
        return error_response

    logger.info(f"Parsed data: {validated_data}")

    if validated_data.get("alert"):
        # If request has alert key, process it as a alert
        container_id, artifact_ids = process_alert(validated_data, soar_rest_client, container_label)

    if validated_data.get("event_type"):
        # If request has event_type key, process it as a event
        container_id, artifact_ids = process_feed(validated_data, soar_rest_client, container_label)

    # Return success response with all created IDs
    return create_success_response(container_id, artifact_ids)
