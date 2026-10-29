/**
 * VerifiX API Client
 * Primary path: Proxied through Vite dev/preview server (/api -> 127.0.0.1:8000)
 * Fallback path: Direct HTTP connection to FastAPI on http://127.0.0.1:8000
 */

export class ApiError extends Error {
  constructor(message, status, details = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

/**
 * Execute request with automatic fallback between Vite proxy and direct backend
 */
async function apiFetch(path, options = {}) {
  // 1. Try proxied path first (/api/...)
  try {
    const res = await fetch(`/api${path}`, options);
    // If not a proxy miss (404) or gateway error (502/504), return the response
    if (res.status !== 404 && res.status !== 502 && res.status !== 504) {
      return res;
    }
  } catch {
    // Network failure on proxy route, attempt fallback below
  }

  // 2. Direct fallback to FastAPI on 127.0.0.1:8000
  try {
    return await fetch(`http://127.0.0.1:8000${path}`, options);
  } catch (err) {
    throw new ApiError(`Cannot connect to backend (${err.message})`, 0);
  }
}

/**
 * Check backend liveness via GET /health
 */
export async function checkHealth() {
  try {
    const res = await apiFetch('/health');
    if (!res.ok) {
      throw new ApiError(`Health check failed with status ${res.status}`, res.status);
    }
    return await res.json();
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(`Cannot connect to backend (${err.message})`, 0);
  }
}

/**
 * Get project metadata via GET /
 */
export async function getProjectInfo() {
  try {
    const res = await apiFetch('/');
    if (!res.ok) {
      throw new ApiError(`Project query failed with status ${res.status}`, res.status);
    }
    return await res.json();
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(`Cannot query project info (${err.message})`, 0);
  }
}

/**
 * Submit source snippet to POST /analyze
 * Structured scan workflow: AST Static Scan -> Offline Reasoning -> Audit Log
 */
export async function analyzeSource(source, filename = '<submitted>') {
  if (!source || !source.trim()) {
    throw new ApiError('Source code cannot be empty', 422);
  }

  try {
    const res = await apiFetch('/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        source,
        filename: filename || '<submitted>',
      }),
    });

    const data = await res.json();

    if (!res.ok) {
      const errorMsg = data?.detail || `Analysis failed with status ${res.status}`;
      throw new ApiError(
        typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg),
        res.status,
        data
      );
    }

    return data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(`Failed to reach analysis endpoint: ${err.message}`, 0);
  }
}

/**
 * Trigger static scan of target file on disk via POST /scan
 */
export async function scanTargetFile() {
  try {
    const res = await apiFetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const data = await res.json();

    if (!res.ok) {
      const errorMsg = data?.detail || `Scan failed with status ${res.status}`;
      throw new ApiError(errorMsg, res.status, data);
    }

    return data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(`Failed to reach scan endpoint: ${err.message}`, 0);
  }
}

/**
 * Request a registered sandbox patch from the FastAPI backend.
 * The backend must restrict this operation to approved rules and
 * must never modify the original source file.
 */
export async function applySandboxPatch(rule = 'PY002') {
  try {
    const res = await apiFetch('/patch', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rule }),
    });

    const data = await res.json();

    if (!res.ok) {
      const errorMsg = data?.detail || `Patch failed with status ${res.status}`;
      throw new ApiError(
        typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg),
        res.status,
        data
      );
    }

    return data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(`Failed to reach patch endpoint: ${err.message}`, 0);
  }
}
