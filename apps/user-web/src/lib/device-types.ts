export type DeviceStatus =
  | 'OFFLINE'
  | 'IDLE'
  | 'SCANNING'
  | 'ERROR';

export interface Device {
  id: string;
  hostname: string;
  operatingSystem: string;
  architecture: string | null;
  agentVersion: string;
  status: DeviceStatus;
  lastSeenAt: string | null;
  createdAt: string;
}

export interface CreateEnrollmentCodeResponse {
  code: string;
  expectedAgentName: string;
  bootstrapCommand: string;
  expiresAt: string;
}
