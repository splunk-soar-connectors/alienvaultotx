# File: alienvaultotx_consts.py
#
# Copyright (c) 2019-2021 Splunk Inc.
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
#
#
# Status/Progress Messages
OTX_ERR_CODE_UNAVAILABLE = "Error code unavailable"
OTX_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or the action parameters."
OTX_SUCC_CONNECTIVITY_TEST = "Test connectivity passed"
OTX_ERR_CONNECTIVITY_TEST = "Test connectivity failed"
OTX_ERR_MALFORMED_DOMAIN = "Malformed domain"
OTX_ERR_MALFORMED_IP = "Malformed IP address"
OTX_ERR_NO_PULSE_FOUND = "No pulse found"

# JSON keys used in params, result, summary etc.
OTX_JSON_API_KEY = "api_key"
OTX_JSON_DOMAIN = "domain"
OTX_JSON_IP = "ip"
OTX_JSON_HASH = "hash"
OTX_JSON_URL = "url"
OTX_JSON_PULSE_ID = "pulse_id"
OTX_JSON_PULSE_INFO = "pulse_info"
OTX_JSON_PULSES = "pulses"
OTX_JSON_INDICATORS = "indicators"
OTX_JSON_NUM_PULSES = "num_pulses"
OTX_JSON_NUM_INDICATORS = "num_indicators"

# Endpoints
OTX_BASE_URL = "https://otx.alienvault.com"
OTX_TEST_CONNECTIVITY_ENDPOINT = "/api/v1/users/me"
OTX_DOMAIN_REPUTATION_ENDPOINT = "/api/v1/indicators/domain/{0}/general"
OTX_IPV4_REPUTATION_ENDPOINT = "/api/v1/indicators/IPv4/{0}/general"
OTX_IPV6_REPUTATION_ENDPOINT = "/api/v1/indicators/IPv6/{0}/general"
OTX_FILE_REPUTATION_ENDPOINT = "/api/v1/indicators/file/{0}/general"
OTX_URL_REPUTATION_ENDPOINT = "/api/v1/indicators/url/{0}/general"
OTX_GET_PULSES_ENDPOINT = "/api/v1/pulses/{0}"

# Action names
OTX_TEST_CONNECTIVITY_ACTION = "test_connectivity"
OTX_DOMAIN_REPUTATION_ACTION = "domain_reputation"
OTX_IP_REPUTATION_ACTION = "ip_reputation"
OTX_FILE_REPUTATION_ACTION = "file_reputation"
OTX_URL_REPUTATION_ACTION = "url_reputation"
OTX_GET_PULSES_ACTION = "get_pulses"
