"""API schemas (Pydantic models) for request/response validation.

Centralized schemas for all API routes.
"""

from __future__ import annotations

# Auth schemas
from mcp_acp_extended.api.schemas.auth import (
    AuthStatusResponse,
    DeviceFlowPollResponse,
    DeviceFlowStartResponse,
    FederatedLogoutResponse,
    LogoutResponse,
    NotifyResponse,
)

# Config schemas
from mcp_acp_extended.api.schemas.config import (
    AuthConfigResponse,
    AuthConfigUpdate,
    BackendConfigResponse,
    BackendConfigUpdate,
    ConfigChange,
    ConfigComparisonResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    HITLConfigResponse,
    HITLConfigUpdate,
    HttpTransportResponse,
    HttpTransportUpdate,
    LoggingConfigResponse,
    LoggingConfigUpdate,
    MTLSConfigResponse,
    MTLSConfigUpdate,
    OIDCConfigResponse,
    OIDCConfigUpdate,
    ProxyConfigResponse,
    ProxyConfigUpdate,
    StdioTransportResponse,
    StdioTransportUpdate,
)

# Policy schemas
from mcp_acp_extended.api.schemas.policy import (
    PolicyFullUpdate,
    PolicyResponse,
    PolicyRuleCreate,
    PolicyRuleMutationResponse,
    PolicyRuleResponse,
)

# Approvals schemas
from mcp_acp_extended.api.schemas.approvals import (
    ApprovalCacheResponse,
    CachedApprovalResponse,
    ClearApprovalsResponse,
    DeleteApprovalResponse,
)

# Control schemas
from mcp_acp_extended.api.schemas.control import (
    ProxyStatus,
    ReloadResponse,
)

# Pending schemas
from mcp_acp_extended.api.schemas.pending import (
    ApprovalActionResponse,
    PendingApprovalResponse,
)

# Proxies schemas
from mcp_acp_extended.api.schemas.proxies import (
    ProxyResponse,
    StatsResponse,
)

# Sessions schemas
from mcp_acp_extended.api.schemas.sessions import (
    AuthSessionResponse,
)

# Logs schemas
from mcp_acp_extended.api.schemas.logs import (
    LogFileInfo,
    LogFolderInfo,
    LogsMetadataResponse,
    LogsResponse,
)

# Incidents schemas
from mcp_acp_extended.api.schemas.incidents import (
    IncidentsSummary,
)

__all__ = [
    # Auth
    "AuthStatusResponse",
    "DeviceFlowPollResponse",
    "DeviceFlowStartResponse",
    "FederatedLogoutResponse",
    "LogoutResponse",
    "NotifyResponse",
    # Config
    "AuthConfigResponse",
    "AuthConfigUpdate",
    "BackendConfigResponse",
    "BackendConfigUpdate",
    "ConfigChange",
    "ConfigComparisonResponse",
    "ConfigResponse",
    "ConfigUpdateRequest",
    "ConfigUpdateResponse",
    "HITLConfigResponse",
    "HITLConfigUpdate",
    "HttpTransportResponse",
    "HttpTransportUpdate",
    "LoggingConfigResponse",
    "LoggingConfigUpdate",
    "MTLSConfigResponse",
    "MTLSConfigUpdate",
    "OIDCConfigResponse",
    "OIDCConfigUpdate",
    "ProxyConfigResponse",
    "ProxyConfigUpdate",
    "StdioTransportResponse",
    "StdioTransportUpdate",
    # Policy
    "PolicyFullUpdate",
    "PolicyResponse",
    "PolicyRuleCreate",
    "PolicyRuleMutationResponse",
    "PolicyRuleResponse",
    # Approvals
    "ApprovalCacheResponse",
    "CachedApprovalResponse",
    "ClearApprovalsResponse",
    "DeleteApprovalResponse",
    # Control
    "ProxyStatus",
    "ReloadResponse",
    # Pending
    "ApprovalActionResponse",
    "PendingApprovalResponse",
    # Proxies
    "ProxyResponse",
    "StatsResponse",
    # Sessions
    "AuthSessionResponse",
    # Logs
    "LogFileInfo",
    "LogFolderInfo",
    "LogsMetadataResponse",
    "LogsResponse",
    # Incidents
    "IncidentsSummary",
]
