import type {
  SystemStatus,
  AccountInfo,
  Position,
  DecisionRecord,
  Statistics,
  TraderInfo,
  CompetitionData,
} from '../types';

const API_BASE = '/api';
const AUTH_TOKEN_STORAGE_KEY = 'nofx:auth_token';
const AUTH_TOKEN_EXP_STORAGE_KEY = 'nofx:auth_token_exp';

type RequestOptions = RequestInit & {
  skipAuth?: boolean;
  skipUnauthorizedHandler?: boolean;
};

type UnauthorizedHandler = () => void;

let unauthorizedHandler: UnauthorizedHandler | null = null;

export interface LoginResponse {
  token: string;
  expires_at?: string;
  expires_in?: number;
}

function isBrowser(): boolean {
  return typeof window !== 'undefined';
}

function buildHeaders(headersInit?: HeadersInit, includeAuth = true): Headers {
  const headers = new Headers(headersInit ?? {});
  if (includeAuth) {
    const token = getStoredToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  }
  return headers;
}

async function handleResponse<T>(
  response: Response,
  { skipUnauthorizedHandler }: { skipUnauthorizedHandler?: boolean }
): Promise<T> {
  if (response.status === 401 && !skipUnauthorizedHandler) {
    if (unauthorizedHandler) {
      unauthorizedHandler();
    }
    throw new Error('未授权，请重新登录');
  }

  if (!response.ok) {
    let message = `请求失败 (${response.status})`;
    try {
      const data = await response.json();
      if (typeof data === 'object' && data && 'error' in data) {
        message = String((data as { error: unknown }).error);
      }
    } catch {
      try {
        const text = await response.text();
        if (text) {
          message = text;
        }
      } catch {
        // ignore
      }
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return null as T;
  }

  return response.json() as Promise<T>;
}

async function request<T>(path: string, options: RequestOptions = {}, isAPI = true): Promise<T> {
  const { skipAuth, skipUnauthorizedHandler, ...fetchOptions } = options;
  const url = isAPI ? `${API_BASE}${path}` : path;
  const headers = buildHeaders(fetchOptions.headers, !skipAuth);

  const response = await fetch(url, {
    ...fetchOptions,
    headers,
  });

  return handleResponse<T>(response, { skipUnauthorizedHandler });
}

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  unauthorizedHandler = handler;
}

export function getStoredToken(): string | null {
  if (!isBrowser()) {
    return null;
  }
  return window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
}

export function getStoredExpiry(): string | null {
  if (!isBrowser()) {
    return null;
  }
  return window.localStorage.getItem(AUTH_TOKEN_EXP_STORAGE_KEY);
}

export function saveAuthSession(token: string, expiresAt?: string) {
  if (!isBrowser()) {
    return;
  }
  window.localStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token);
  if (expiresAt) {
    window.localStorage.setItem(AUTH_TOKEN_EXP_STORAGE_KEY, expiresAt);
  } else {
    window.localStorage.removeItem(AUTH_TOKEN_EXP_STORAGE_KEY);
  }
}

export function clearAuthSession() {
  if (!isBrowser()) {
    return;
  }
  window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
  window.localStorage.removeItem(AUTH_TOKEN_EXP_STORAGE_KEY);
}

export const api = {
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await request<LoginResponse>('/auth/login', {
      method: 'POST',
      skipAuth: true,
      skipUnauthorizedHandler: true,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    }, false);

    return response;
  },

  // 竞赛相关接口
  async getCompetition(): Promise<CompetitionData> {
    return request<CompetitionData>('/competition');
  },

  async getTraders(): Promise<TraderInfo[]> {
    return request<TraderInfo[]>('/traders');
  },

  // 获取系统状态（支持trader_id）
  async getStatus(traderId?: string): Promise<SystemStatus> {
    const url = traderId ? `/status?trader_id=${traderId}` : '/status';
    return request<SystemStatus>(url);
  },

  // 获取账户信息（支持trader_id）
  async getAccount(traderId?: string): Promise<AccountInfo> {
    const url = traderId ? `/account?trader_id=${traderId}` : '/account';
    return request<AccountInfo>(url, {
      cache: 'no-store',
      headers: {
        'Cache-Control': 'no-cache',
      },
    });
  },

  // 获取持仓列表（支持trader_id）
  async getPositions(traderId?: string): Promise<Position[]> {
    const url = traderId ? `/positions?trader_id=${traderId}` : '/positions';
    return request<Position[]>(url);
  },

  // 获取决策日志（支持trader_id）
  async getDecisions(traderId?: string): Promise<DecisionRecord[]> {
    const url = traderId ? `/decisions?trader_id=${traderId}` : '/decisions';
    return request<DecisionRecord[]>(url);
  },

  // 获取最新决策（支持trader_id）
  async getLatestDecisions(traderId?: string): Promise<DecisionRecord[]> {
    const url = traderId ? `/decisions/latest?trader_id=${traderId}` : '/decisions/latest';
    return request<DecisionRecord[]>(url);
  },

  // 获取统计信息（支持trader_id）
  async getStatistics(traderId?: string): Promise<Statistics> {
    const url = traderId ? `/statistics?trader_id=${traderId}` : '/statistics';
    return request<Statistics>(url);
  },

  // 获取收益率历史数据（支持trader_id）
  async getEquityHistory(traderId?: string): Promise<any[]> {
    const url = traderId ? `/equity-history?trader_id=${traderId}` : '/equity-history';
    return request<any[]>(url);
  },

  // 获取AI学习表现分析（支持trader_id）
  async getPerformance(traderId?: string): Promise<any> {
    const url = traderId ? `/performance?trader_id=${traderId}` : '/performance';
    return request<any>(url);
  },
};
