import { apiGet, apiPut } from './client'

// =============================================================================
// Response Types
// =============================================================================

export interface StdioTransportConfig {
  command: string
  args: string[]
}

export interface HttpTransportConfig {
  url: string
  timeout: number
}

export type TransportType = 'stdio' | 'streamablehttp' | 'auto'

export interface BackendConfig {
  server_name: string
  transport: TransportType | null
  stdio: StdioTransportConfig | null
  http: HttpTransportConfig | null
}

export interface LoggingConfig {
  log_dir: string
  log_level: string
  include_payloads: boolean
}

export interface OIDCConfig {
  issuer: string
  client_id: string
  audience: string
  scopes: string[]
}

export interface MTLSConfig {
  client_cert_path: string
  client_key_path: string
  ca_bundle_path: string
}

export interface AuthConfig {
  oidc: OIDCConfig | null
  mtls: MTLSConfig | null
}

export interface ProxyConfig {
  name: string
}

export interface ConfigResponse {
  backend: BackendConfig
  logging: LoggingConfig
  auth: AuthConfig | null
  proxy: ProxyConfig
  config_path: string
  requires_restart_for_changes: boolean
}

export interface ConfigUpdateResponse {
  config: ConfigResponse
  message: string
}

// =============================================================================
// Update Request Types
// =============================================================================

export interface StdioTransportUpdate {
  command?: string
  args?: string[]
}

export interface HttpTransportUpdate {
  url?: string
  timeout?: number
}

export interface BackendConfigUpdate {
  server_name?: string
  transport?: TransportType
  stdio?: StdioTransportUpdate
  http?: HttpTransportUpdate
}

export interface LoggingConfigUpdate {
  log_dir?: string
  log_level?: string
  include_payloads?: boolean
}

export interface OIDCConfigUpdate {
  issuer?: string
  client_id?: string
  audience?: string
  scopes?: string[]
}

export interface MTLSConfigUpdate {
  client_cert_path?: string
  client_key_path?: string
  ca_bundle_path?: string
}

export interface AuthConfigUpdate {
  oidc?: OIDCConfigUpdate
  mtls?: MTLSConfigUpdate
}

export interface ProxyConfigUpdate {
  name?: string
}

export interface ConfigUpdateRequest {
  logging?: LoggingConfigUpdate
  backend?: BackendConfigUpdate
  proxy?: ProxyConfigUpdate
  auth?: AuthConfigUpdate
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Get current configuration.
 */
export async function getConfig(): Promise<ConfigResponse> {
  return apiGet<ConfigResponse>('/config')
}

/**
 * Update configuration.
 * Only specified fields will be updated.
 * Changes take effect on proxy restart.
 */
export async function updateConfig(
  updates: ConfigUpdateRequest
): Promise<ConfigUpdateResponse> {
  return apiPut<ConfigUpdateResponse>('/config', updates)
}
