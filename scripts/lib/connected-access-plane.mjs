// M08.16 — THE PLANE LEG. One isolated daemon, one stub OAuth provider, one real connection ceremony, and
// the Hypervisor cockpit fetched from a serve pointed at that daemon.
//
// WHY THIS LEG AND NOT A UNIT TEST. The claim under test is that a SURFACE renders the daemon's posture
// rather than deriving one. That is a claim about a running serve reading a running daemon, and the defect
// this unit exists to end — a credential-presence stamp rendered as the word "connected" — was invisible to
// every source pin for as long as it shipped, because the pin would have read exactly what the author
// intended. Only the rendered bytes settle it.
//
// The stub provider is the one M03.16's gate drives, in its minimal form: discovery, authorize, token and
// userinfo. Nothing here reaches the network; the daemon talks to a loopback server this file started.

const PKCE = (verifier, crypto) => crypto.createHash("sha256").update(verifier).digest("base64url");

export async function planeLeg({ ROOT, APP_DIR, SERVE, LIB, freePort, waitFor, spawn, http, crypto, fs, os, path, sanitizedVerifierBaseEnv }) {
  const started = Date.now();
  const findings = [];
  const f = (x) => findings.push(x);
  const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
  if (!fs.existsSync(daemonBinary)) return { findings: ["daemon_binary_absent"], blocked: true, seconds: 0 };

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-connected-access-"));
  let daemon = null;
  let serve = null;
  let provider = null;
  let daemonLog = "";

  // ---- the stub provider: discovery, authorize, token, userinfo. Loopback only.
  const state = { subject: "acct-1", tenant: "tenant-1", codes: new Map(), revoked: false, returnedScope: "mail.read" };
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const providerServer = await new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      const origin = `http://127.0.0.1:${server.address().port}`;
      const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
      let raw = ""; for await (const chunk of req) raw += chunk;
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return send(200, { issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, registration_endpoint: `${origin}/register`, userinfo_endpoint: `${origin}/userinfo` });
      }
      if (url.pathname === "/register") return send(201, { client_id: "dcr_1" });
      if (url.pathname === "/authorize") {
        const code = `code_${crypto.randomBytes(8).toString("hex")}`;
        state.codes.set(code, { challenge: url.searchParams.get("code_challenge"), redirect: url.searchParams.get("redirect_uri"), scope: url.searchParams.get("scope") });
        res.writeHead(302, { location: `${url.searchParams.get("redirect_uri")}?state=${encodeURIComponent(url.searchParams.get("state") ?? "")}&code=${code}` });
        return res.end();
      }
      if (url.pathname === "/token") {
        const form = new URLSearchParams(raw);
        const issued = state.codes.get(form.get("code"));
        if (!issued) return send(400, { error: "invalid_grant" });
        if (PKCE(form.get("code_verifier") ?? "", crypto) !== issued.challenge) return send(400, { error: "invalid_grant", error_description: "pkce" });
        state.codes.delete(form.get("code"));
        return send(200, {
          access_token: `at_${crypto.randomBytes(12).toString("hex")}`,
          refresh_token: `rt_${crypto.randomBytes(12).toString("hex")}`,
          token_type: "bearer",
          expires_in: 3600,
          // The provider returns FEWER scopes than were requested — the ordinary case, and the one a
          // surface that renders only "requested" gets wrong.
          scope: state.returnedScope,
          id_token: `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: state.subject, tid: state.tenant, iss: "stub" })}.sig`,
        });
      }
      if (url.pathname === "/userinfo") {
        if (state.revoked) return send(401, { error: "invalid_token" });
        return send(200, { sub: state.subject, tid: state.tenant });
      }
      send(404, { error: "not_found" });
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
  provider = providerServer;
  const providerOrigin = `http://127.0.0.1:${providerServer.address().port}`;

  try {
    // ---- the daemon
    const daemonPort = await freePort();
    const DAEMON = `http://127.0.0.1:${daemonPort}`;
    daemon = spawn(daemonBinary, [], {
      cwd: ROOT,
      env: {
        ...sanitizedVerifierBaseEnv(process.env),
        IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
        IOI_HYPERVISOR_DATA_DIR: dataDir,
        IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
        IOI_WALLET_SECRET_PASS: "ioi-connected-access-verifier",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-40000); });
    daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-40000); });
    if (!(await waitFor(`${DAEMON}/healthz`, 90000))) {
      return { findings: [`daemon_never_became_healthy:${daemonLog.slice(-400)}`], blocked: true, seconds: Math.round((Date.now() - started) / 1000) };
    }

    // ---- one operator session
    const token = (() => {
      for (const name of fs.readdirSync(dataDir).filter((x) => /\.log$/u.test(x)).reverse()) {
        const m = fs.readFileSync(path.join(dataDir, name), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu);
        if (m) return m.at(-1);
      }
      return (daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu) ?? []).at(-1) ?? null;
    })();
    let cookie = "";
    const jd = async (base, tail, init = {}) => {
      const r = await fetch(`${base}${tail}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...(init.anonymous ? {} : cookie ? { cookie } : {}), ...(init.headers ?? {}) } }).catch((e) => ({ status: 0, text: async () => String(e) }));
      const text = await r.text().catch(() => "");
      let body = {};
      try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text.slice(0, 300) }; }
      return { status: r.status, body, text, headers: r.headers };
    };
    const boot = await jd(DAEMON, "/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "connected-access-pass-1", email: "connected-access@ioi.local" }) });
    cookie = boot.body?.session_token ? `ioi_session=${boot.body.session_token}` : "";
    if (!cookie) return { findings: [`bootstrap:${boot.status}:${JSON.stringify(boot.body).slice(0, 200)}`], blocked: true, seconds: Math.round((Date.now() - started) / 1000) };
    const who = (await jd(DAEMON, "/v1/hypervisor/auth/whoami")).body;
    const OWNER = (who.principal?.tenant_refs ?? []).find((t) => String(t).startsWith("org://")) ?? "org://local";

    // ---- the serve, pointed at THIS daemon
    const servePort = await freePort();
    const productUiPort = await freePort();
    const SERVE_URL = `http://127.0.0.1:${servePort}`;
    serve = spawn(process.execPath, [SERVE], {
      cwd: APP_DIR,
      env: {
        ...sanitizedVerifierBaseEnv(process.env),
        PORT: String(servePort),
        PRODUCT_UI_PORT: String(productUiPort),
        IOI_PRODUCT_UI_PUBLIC: path.join(APP_DIR, "product-ui", "owned", "public"),
        IOI_HYPERVISOR_DAEMON_URL: DAEMON,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let serveLog = "";
    serve.stdout.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-20000); });
    serve.stderr.on("data", (c) => { serveLog = `${serveLog}${c}`.slice(-20000); });
    if (!(await waitFor(`${SERVE_URL}/__ioi/login`, 90000))) {
      return { findings: [`serve_never_came_up:${serveLog.slice(-300)}`], blocked: true, seconds: Math.round((Date.now() - started) / 1000) };
    }

    // ---- a connector with a real OAuth profile pointed at the stub
    const connector = await jd(DAEMON, "/v1/hypervisor/connectors", {
      method: "POST",
      body: JSON.stringify({
        name: "Stub provider", service: "stub", kind: "http",
        base_url: providerOrigin, requires_credential: true,
        auth_profile: {
          type: "oauth_authcode_pkce",
          authorization_endpoint: `${providerOrigin}/authorize`,
          token_endpoint: `${providerOrigin}/token`,
          userinfo_endpoint: `${providerOrigin}/userinfo`,
          client_id: "client_1",
          client_secret: "super-secret-value",
          scopes: ["mail.read", "mail.send"],
        },
      }),
    });
    // THE DAEMON DERIVES THE CONNECTOR ID (`conn_<hash>` over service, name and base url); it is not
    // taken from the body. Reading it back is the only correct way to name the thing just registered —
    // assuming a caller-chosen id is how this leg first failed with a 404 on its own connector.
    const CONNECTOR_ID = connector.body?.connector?.connector_id ?? "";
    if (connector.body?.ok !== true || !CONNECTOR_ID) {
      f(`connector_register:${connector.status}:${JSON.stringify(connector.body).slice(0, 220)}`);
      return { findings, seconds: Math.round((Date.now() - started) / 1000) };
    }

    // THE REDACTION, MEASURED ON THE WIRE. The list must not carry the sealed secret and must say whether
    // a confidential client is configured.
    const list = await jd(DAEMON, "/v1/hypervisor/connectors");
    if (/sealed_client_secret/u.test(list.text)) f("the connector list still serves the sealed client secret");
    if (/super-secret-value/u.test(list.text)) f("the connector list serves the PLAINTEXT client secret");
    const listed = (list.body.connectors ?? []).find((c) => c.connector_id === CONNECTOR_ID);
    if (listed?.auth_profile?.confidential_client_configured !== true) f(`the presence flag is ${listed?.auth_profile?.confidential_client_configured}, not true`);

    // ---- one real ceremony: start, follow the provider's redirect, complete
    const REDIRECT = `${SERVE_URL}/__ioi/integrations/oauth/callback`;
    const start = await jd(DAEMON, "/v1/hypervisor/auth/connections/authorization/start", {
      method: "POST",
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "cac-start-1", connector_id: CONNECTOR_ID, redirect_uri: REDIRECT, requested_scopes: ["mail.read", "mail.send"] }),
    });
    // The daemon names it `authorize_url` and returns it at the top level; M03.16's own gate reads it
    // there, and guessing `authorization_url` on the ceremony object is how this leg first failed on a 201.
    const authorizeUrl = start.body?.authorize_url ?? "";
    if (!authorizeUrl) {
      f(`ceremony_start:${start.status}:${JSON.stringify(start.body).slice(0, 300)}`);
      return { findings, seconds: Math.round((Date.now() - started) / 1000) };
    }
    const redirected = await fetch(authorizeUrl, { redirect: "manual" }).catch(() => null);
    const location = redirected?.headers?.get("location") ?? "";
    const code = new URL(location, SERVE_URL).searchParams.get("code") ?? "";
    if (!code) f(`authorize_redirect_carried_no_code:${location.slice(0, 160)}`);
    const complete = await jd(DAEMON, "/v1/hypervisor/auth/connections/authorization/complete", {
      method: "POST",
      // Completion is keyed by the STATE the provider echoed, not by a ceremony ref: the daemon resolves
      // the ceremony from the state it issued, which is what makes a replayed or forged state refusable.
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "cac-complete-1", code, state: new URL(location, SERVE_URL).searchParams.get("state") }),
    });
    if (complete.status !== 200 && complete.status !== 201) f(`ceremony_complete:${complete.status}:${JSON.stringify(complete.body).slice(0, 300)}`);

    // ---- the daemon's own connection record, and the projection the surface should be rendering
    const connections = await jd(DAEMON, "/v1/hypervisor/auth/connections");
    // The LIST is a summary of six members; the full record — provider verification, returned scopes,
    // custody profile — comes from the detail route under `current`. Reading the summary and calling it
    // the record is how a posture gets assembled from members the daemon never stated.
    const bare = (ref) => String(ref ?? "").replace(/^connector:\/\//u, "");
    const summary = (connections.body.connections ?? []).find((c) => bare(c.connector_ref) === CONNECTOR_ID);
    const detail = summary
      ? (await jd(DAEMON, `/v1/hypervisor/auth/connections/${encodeURIComponent(summary.connection_id ?? summary.connection_ref)}`)).body
      : {};
    const record = detail?.current ?? null;
    if (!record) {
      f(`no_connection_record_after_a_completed_ceremony:${JSON.stringify(connections.body).slice(0, 220)}`);
      return { findings, seconds: Math.round((Date.now() - started) / 1000) };
    }
    const expected = LIB.projectConnection(record, { now: new Date().toISOString() });
    const projectionFindings = LIB.projectionFindings(expected, record, { where: "daemon record" });
    if (projectionFindings.length) f(`the daemon's own record does not project cleanly:${projectionFindings.slice(0, 2).join("|")}`);

    // RETURNED IS NOT REQUESTED. The stub returned one scope where two were asked for; if the record says
    // otherwise the ceremony is not recording what the provider said.
    if (JSON.stringify(record.provider_granted_scopes) !== JSON.stringify(["mail.read"])) {
      f(`the record's returned scopes read ${JSON.stringify(record.provider_granted_scopes)}, the provider returned ["mail.read"]`);
    }

    // ---- THE COCKPIT, RENDERED
    const page = await jd(SERVE_URL, "/__ioi/connections");
    if (page.status !== 200) f(`cockpit_http:${page.status}`);
    const html = page.text ?? "";
    for (const bad of LIB.secretFindings(html, { where: "the rendered cockpit" })) f(bad);
    if (/super-secret-value/u.test(html)) f("the rendered cockpit carries the PLAINTEXT client secret");
    const posture = (html.match(/data-ioi-connection-posture="([^"]*)"/u) ?? [])[1] ?? "";
    if (posture !== expected.effective_posture) f(`the cockpit renders the posture ${posture || "(none)"}, the daemon's record projects ${expected.effective_posture}`);
    const reachability = (html.match(/data-ioi-provider-reachability="([^"]*)"/u) ?? [])[1] ?? "";
    if (reachability !== expected.provider_reachability) f(`the cockpit renders the reachability ${reachability || "(none)"}, the record's is ${expected.provider_reachability}`);
    const epoch = (html.match(/data-ioi-connection-epoch="([^"]*)"/u) ?? [])[1] ?? "";
    if (epoch !== String(expected.connection_revocation_epoch)) f(`the cockpit renders the epoch ${epoch || "(none)"}, the record's is ${expected.connection_revocation_epoch}`);
    if (!html.includes("Scopes returned by the provider")) f("the cockpit does not separate returned scopes from requested");
    if (!html.includes("not a wallet authority grant")) f("the cockpit does not disclaim that returned scopes are not authority");

    // ---- DISCONNECT, AND READ THE PAGE AGAIN. The epoch advances and the posture must follow.
    // The route takes the daemon's own `{connector_id}~{principal-slug}` id, not the connection:// ref —
    // it says so by name (`provider_connection_id_not_canonical`) rather than accepting either.
    const disconnect = await jd(DAEMON, `/v1/hypervisor/auth/connections/${encodeURIComponent(summary.connection_id)}/disconnect`, {
      method: "POST",
      // The route admits a CLOSED field set and says so: the ceremony, the binding and every provider
      // fact are derived, never authored, so a caller-supplied expected version is refused by name.
      // A successor names the EXACT current head — the chain refuses a blind write, which is what makes
      // two operators disconnecting at once resolve to one admitted successor rather than a fork.
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: "cac-disconnect-1", expected_head: detail?.head, reason: "operator disconnect" }),
    });
    if (disconnect.status !== 200 && disconnect.status !== 201) {
      f(`disconnect:${disconnect.status}:${JSON.stringify(disconnect.body).slice(0, 220)}`);
    } else {
      const after = (await jd(DAEMON, "/v1/hypervisor/auth/connections")).body.connections ?? [];
      const afterSummary = after.filter((c) => bare(c.connector_ref) === CONNECTOR_ID).sort((a, b) => (b.connection_version ?? 0) - (a.connection_version ?? 0))[0];
      const head = afterSummary
        ? (await jd(DAEMON, `/v1/hypervisor/auth/connections/${encodeURIComponent(afterSummary.connection_id ?? afterSummary.connection_ref)}`)).body?.current
        : null;
      if (!head) f("the connection vanished on disconnect rather than becoming a successor version");
      else {
        if ((head.connection_revocation_epoch ?? 0) <= (record.connection_revocation_epoch ?? 0)) {
          f(`the epoch did not advance on disconnect: ${record.connection_revocation_epoch} → ${head.connection_revocation_epoch}`);
        }
        const afterProjection = LIB.projectConnection(head, { now: new Date().toISOString() });
        if (!afterProjection.use_is_fenced) f(`a disconnected connection projects unfenced: ${afterProjection.effective_posture}`);
        const page2 = await jd(SERVE_URL, "/__ioi/connections");
        const posture2 = (page2.text.match(/data-ioi-connection-posture="([^"]*)"/u) ?? [])[1] ?? "";
        if (posture2 !== afterProjection.effective_posture) {
          f(`after disconnect the cockpit renders ${posture2 || "(none)"}, the record projects ${afterProjection.effective_posture}`);
        }
        if (/\bconnected\b/iu.test(page2.text) && afterProjection.effective_posture !== "active") {
          f("after disconnect the cockpit still renders the word \"connected\"");
        }
      }
    }
  } catch (error) {
    f(`plane_threw:${String(error?.stack ?? error).slice(0, 300)}`);
  } finally {
    for (const child of [serve, daemon]) {
      if (!child) continue;
      try { child.kill("SIGTERM"); } catch { /* gone */ }
    }
    await new Promise((r) => setTimeout(r, 400));
    for (const child of [serve, daemon]) { try { child?.kill("SIGKILL"); } catch { /* gone */ } }
    try { provider?.close(); } catch { /* gone */ }
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
  return { findings, seconds: Math.round((Date.now() - started) / 1000) };
}
