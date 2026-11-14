(() => {
  const cfg = window.SCANNER_SUPABASE;
  if (!cfg?.url || !cfg?.publishableKey) throw new Error("Scanner authentication configuration is missing.");
  const STORE = "anish.scanner.auth.v1";
  let cached = null;

  function read() {
    if (cached) return cached;
    try { cached = JSON.parse(sessionStorage.getItem(STORE) || "null"); } catch { cached = null; }
    return cached;
  }
  function save(session) {
    if (!session?.access_token || !session?.refresh_token) throw new Error("Authentication server returned an invalid session.");
    cached = {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at || (Math.floor(Date.now()/1000) + Number(session.expires_in || 3600)),
      user: session.user || read()?.user || null
    };
    sessionStorage.setItem(STORE, JSON.stringify(cached));
    return cached;
  }
  async function request(path, options = {}, token) {
    const headers = {
      apikey: cfg.publishableKey,
      "Content-Type": "application/json",
      ...(options.headers || {})
    };
    if (token) headers.Authorization = "Bearer " + token;
    const response = await fetch(cfg.url + path, { ...options, headers, cache: "no-store" });
    const raw = await response.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch {}
    if (!response.ok) {
      const message = data?.msg || data?.message || data?.error_description || data?.error || "Request failed (" + response.status + ").";
      const error = new Error(message);
      error.status = response.status;
      error.code = data?.code || data?.error_code || "request_failed";
      throw error;
    }
    return data;
  }
  async function refresh() {
    const s = read();
    if (!s?.refresh_token) return null;
    const session = await request("/auth/v1/token?grant_type=refresh_token", {
      method: "POST",
      body: JSON.stringify({ refresh_token: s.refresh_token })
    });
    return save(session);
  }
  async function getSession(force = false) {
    let s = read();
    if (!s) return null;
    if (force || !s.expires_at || s.expires_at < Math.floor(Date.now()/1000) + 60) {
      try { s = await refresh(); } catch { signOutLocal(); return null; }
    }
    return s;
  }
  function signOutLocal() {
    cached = null;
    sessionStorage.removeItem(STORE);
  }
  async function signUp(email, password, name) {
    const data = await request("/auth/v1/signup", {
      method: "POST",
      body: JSON.stringify({ email, password, data: { name } })
    });
    if (data?.access_token) save(data);
    return data;
  }
  async function signIn(email, password) {
    const data = await request("/auth/v1/token?grant_type=password", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
    return save(data);
  }
  async function user() {
    const s = await getSession();
    if (!s) return null;
    const u = await request("/auth/v1/user", {}, s.access_token);
    const current = read();
    current.user = u;
    save(current);
    return u;
  }
  async function factors() {
    const s = await getSession();
    if (!s) throw new Error("Sign in first.");
    const result = await request("/auth/v1/factors", {}, s.access_token);
    return result?.factors || [];
  }
  async function startMfa(factorId) {
    const s = await getSession();
    if (!s) throw new Error("Sign in first.");
    const challenge = await request("/auth/v1/factors/" + encodeURIComponent(factorId) + "/challenge", {
      method: "POST", body: JSON.stringify({})
    }, s.access_token);
    return challenge;
  }
  async function verifyMfa(factorId, challengeId, code) {
    const s = await getSession();
    if (!s) throw new Error("Sign in first.");
    const session = await request("/auth/v1/factors/" + encodeURIComponent(factorId) + "/verify", {
      method: "POST",
      body: JSON.stringify({ challenge_id: challengeId, code: String(code).trim() })
    }, s.access_token);
    if (session?.access_token) save(session);
    else {
      const refreshed = await refresh();
      if (!refreshed) throw new Error("MFA was verified but the session could not be refreshed.");
    }
    return read();
  }
  async function enrollMfa() {
    const s = await getSession();
    if (!s) throw new Error("Sign in first.");
    const result = await request("/auth/v1/factors", {
      method: "POST",
      body: JSON.stringify({ factor_type: "totp", friendly_name: "ANISH ENTERPRISES Scanner" })
    }, s.access_token);
    return result;
  }
  async function authenticatedFetch(url, options = {}) {
    const s = await getSession();
    if (!s) throw new Error("Your session has expired. Sign in again.");
    const headers = { ...(options.headers || {}), Authorization: "Bearer " + s.access_token };
    return fetch(url, { ...options, headers, cache: "no-store" });
  }
  async function edge(name, body = {}) {
    const s = await getSession();
    if (!s) throw new Error("Sign in with your approved account.");
    const response = await request("/functions/v1/" + encodeURIComponent(name), {
      method: "POST",
      body: JSON.stringify(body)
    }, s.access_token);
    return response;
  }
  async function rest(table, method, body, query = "") {
    const s = await getSession();
    if (!s) throw new Error("Sign in first.");
    return request("/rest/v1/" + table + (query ? "?" + query : ""), {
      method,
      headers: {
        Prefer: method === "POST" ? "return=representation" : "return=representation",
        "Content-Profile": "public",
        "Accept-Profile": "public"
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }, s.access_token);
  }
  async function signOut() {
    const s = await getSession();
    try { if (s) await request("/auth/v1/logout", { method: "POST" }, s.access_token); } finally { signOutLocal(); }
  }
  window.ScannerAuth = Object.freeze({
    getSession, signUp, signIn, user, factors, startMfa, verifyMfa, enrollMfa,
    authenticatedFetch, edge, rest, signOut, signOutLocal
  });
})();