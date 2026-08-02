export type RoleCode = 'ADMIN' | 'USER';

export type UserStatus =
  | 'ACTIVE'
  | 'DISABLED';

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

export interface PortalLoginResponse {
  user: AuthenticatedUser;
}

export interface UserListItem {
  id: string;
  email: string;
  fullName: string;
  role: RoleCode;
  status: UserStatus;
  lastLoginAt: string | null;
  createdAt: string;
  deviceCount?: number;
  activeDeviceCount?: number;
  hasActiveDevice?: boolean;
}

export interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface UserSummary {
  total: number;
  activeAccounts: number;
  disabledAccounts: number;
  usersWithActiveDevices: number;
  usersWithoutActiveDevices: number;
}

export interface ListUsersResponse {
  data: UserListItem[];
  pagination: Pagination;
  summary?: UserSummary;
}

export interface ApiErrorResponse {
  code?: string;
  message?: string | string[];
  statusCode?: number;
}

export interface CreateUserResponse {
  id?: string;
  email?: string;
  fullName?: string;
  role?: RoleCode;
  status?: UserStatus;
  message?: string;
}
