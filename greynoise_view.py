# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# File: greynoise_view.py
#
# Copyright (c) GreyNoise, 2019-2022.
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


def display_view_ip_reputation(provides, all_app_runs, context):
    """Display a specific view based on the 'provides' parameter.

    It processes the action results from 'all_app_runs' and returns the corresponding view path.

    :param provides: Action names
    :param all_app_runs: List of tuples containing summary and action results
    :param context: A dictionary containing the results
    :return: str
    """
    context["results"] = results = []
    tag_names = []
    cve_ids = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if data and isinstance(data, list):
                if data[0] and isinstance(data[0], dict):
                    tags = data[0].get("internet_scanner_intelligence", {}).get("tags")
                    if tags and isinstance(tags, list):
                        for tag in tags:
                            if tag and isinstance(tag, dict):
                                tag_names.append(tag.get("name"))
                data[0]["tag_names"] = tag_names
            else:
                data = []
            results.append(data)

    context["results"] = results

    if provides == "ip reputation":
        return "views/greynoise_ip_reputation.html"


def display_view_cve_details(provides, all_app_runs, context):
    """Display a specific view based on the 'provides' parameter.

    It processes the action results from 'all_app_runs' and returns the corresponding view path.

    :param provides: Action names
    :param all_app_runs: List of tuples containing summary and action results
    :param context: A dictionary containing the results
    :return: str
    """
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            results.append(data)

    context["results"] = results

    if provides == "get cve details":
        return "views/greynoise_get_cve_details.html"


def display_view_gnql_query(provides, all_app_runs, context):
    """Display a specific view based on the 'provides' parameter.

    It processes the action results from 'all_app_runs' and returns the corresponding view path.

    :param provides: Action names
    :param all_app_runs: List of tuples containing summary and action results
    :param context: A dictionary containing the results
    :return: str
    """
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if isinstance(data, list) and data:
                if isinstance(data[0].get("data"), list) and data[0].get("data"):
                    for ip in data[0].get("data"):
                        tags = ip.get("internet_scanner_intelligence", {}).get("tags")
                        tag_names = []
                        if tags and isinstance(tags, list):
                            for tag in tags:
                                if tag and isinstance(tag, dict):
                                    tag_names.append(tag.get("name"))
                        ip["tag_names"] = tag_names
            else:
                data = []
            results.append(data)

    if provides == "gnql query":
        return "views/greynoise_gnql_query.html"

def display_view_lookup_ips(provides, all_app_runs, context):
    """Display a specific view for multiple IP lookup.

    It processes the action results from 'all_app_runs' and returns the corresponding view path.

    :param provides: Action names
    :param all_app_runs: List of tuples containing summary and action results
    :param context: A dictionary containing the results
    :return: str
    """
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            results.append(data)

    context["results"] = results

    return "views/greynoise_lookup_ips.html"

def display_view_noise_ip_timeline(provides, all_app_runs, context):
    """Display a specific view for IP timeline lookup.

    It processes the action results from 'all_app_runs' and returns the corresponding view path.

    :param provides: Action names
    :param all_app_runs: List of tuples containing summary and action results
    :param context: A dictionary containing the results
    :return: str
    """

    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()

            # Format timestamps in results if they exist
            if data and isinstance(data, list) and len(data) > 0:
                for item in data:
                    if "results" in item:
                        for entry in item["results"]:
                            if "timestamp" in entry:
                                # Convert ISO format to more readable date
                                try:
                                    from datetime import datetime
                                    timestamp = datetime.strptime(entry["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                                    entry["timestamp"] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    # Keep original if parsing fails
                                    pass

            results.append(data)

    return "views/greynoise_noise_ip_timeline.html"