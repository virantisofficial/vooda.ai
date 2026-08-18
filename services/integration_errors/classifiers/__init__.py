# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Per-provider error classifiers.

Each provider gets one module (atlassian.py, ms_graph.py, …).  The
module exports a single ``classify_*`` function that takes a raw
provider response (or a network exception) and returns an
:class:`IntegrationError`.

The classifier is the ONLY place that should know provider-specific
details (which header carries the trace ID, which response codes
mean "auth" vs "permission", which body fields hold the error code).
Keeping it isolated here means adapters never re-implement that
mapping inline.

Family layout (alphabetical):

  atlassian       Confluence + Jira (Cloud REST)
  azure           Azure DevOps (PAT REST) + Azure Storage (SharedKey)
  bitbucket       Bitbucket Cloud (Atlassian-owned, distinct API)
  generic_http    Long-tail providers without distinctive envelopes
                  (asana, box, mattermost, postman, container_registry,
                   Jenkins / CircleCI in cicd_logs).  Also exports
                  ``classify_sdk_error`` for boto3 / Docker CLI paths.
  github          GitHub REST + GitHub Actions
  google          Google APIs (Drive, Workspace) — shared envelope
  linear          Linear GraphQL
  ms_graph        Microsoft Graph (Teams + OneDrive/SharePoint via _msgraph)
  network         Transport-level (DNS, TLS, timeouts) — provider-agnostic
  notion          Notion REST
  salesforce      Salesforce OAuth + REST
  servicenow      ServiceNow REST
  slack           Slack Web API ({ok:false} envelope at HTTP 200)
"""

from .atlassian import classify_atlassian_error
from .azure import classify_azure_blob_error, classify_azure_devops_error
from .bitbucket import classify_bitbucket_error
from .generic_http import classify_http_error, classify_sdk_error
from .github import classify_github_error
from .google import classify_google_error
from .linear import classify_linear_error
from .ms_graph import classify_graph_error, classify_graph_token_error
from .network import classify_network_error
from .notion import classify_notion_error
from .salesforce import classify_salesforce_error, classify_salesforce_token_error
from .servicenow import classify_servicenow_error
from .slack import classify_slack_error

__all__ = [
    "classify_atlassian_error",
    "classify_azure_blob_error",
    "classify_azure_devops_error",
    "classify_bitbucket_error",
    "classify_github_error",
    "classify_google_error",
    "classify_graph_error",
    "classify_graph_token_error",
    "classify_http_error",
    "classify_linear_error",
    "classify_network_error",
    "classify_notion_error",
    "classify_salesforce_error",
    "classify_salesforce_token_error",
    "classify_sdk_error",
    "classify_servicenow_error",
    "classify_slack_error",
]
