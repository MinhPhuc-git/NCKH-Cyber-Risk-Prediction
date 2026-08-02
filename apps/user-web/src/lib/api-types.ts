export type RoleCode = 'ADMIN' | 'USER';

export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string;
  role: RoleCode;
}

export interface BackendLoginResponse {
  accessToken: string;
  tokenType: 'Bearer';
  user: AuthenticatedUser;
}

export interface RegisterResponse {
  id: string;
  email: string;
  fullName: string;
  role: 'USER';
  status: 'ACTIVE';
  createdAt: string;
}

export interface ApiErrorResponse {
  code?: string;
  message?: string | string[];
  statusCode?: number;
}
