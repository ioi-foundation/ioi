import { chromium } from "playwright";
import { createServer } from "node:http";

const normalizePublicKeyOptions = (value) => {
  const options = structuredClone(value.publicKey || value.public_key || value);
  return options;
};

const browserCredential = async (page, mode, publicKey) => page.evaluate(
  async ({ operation, options }) => {
    const fromBase64Url = (value) => {
      const normalized = value.replaceAll("-", "+").replaceAll("_", "/")
        + "=".repeat((4 - (value.length % 4)) % 4);
      const binary = atob(normalized);
      return Uint8Array.from(binary, (character) => character.charCodeAt(0));
    };
    const toBase64Url = (value) => {
      if (value == null) return null;
      const bytes = new Uint8Array(value);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    };
    const decoded = structuredClone(options);
    decoded.challenge = fromBase64Url(decoded.challenge);
    if (operation === "create") {
      decoded.user.id = fromBase64Url(decoded.user.id);
      for (const descriptor of decoded.excludeCredentials || []) {
        descriptor.id = fromBase64Url(descriptor.id);
      }
    } else {
      for (const descriptor of decoded.allowCredentials || []) {
        descriptor.id = fromBase64Url(descriptor.id);
      }
    }
    const credential = operation === "create"
      ? await navigator.credentials.create({ publicKey: decoded })
      : await navigator.credentials.get({ publicKey: decoded });
    if (!credential) throw new Error(`software passkey ${operation} produced no credential`);
    const response = operation === "create"
      ? {
          attestationObject: toBase64Url(credential.response.attestationObject),
          clientDataJSON: toBase64Url(credential.response.clientDataJSON),
          transports: credential.response.getTransports?.() || ["internal"],
        }
      : {
          authenticatorData: toBase64Url(credential.response.authenticatorData),
          clientDataJSON: toBase64Url(credential.response.clientDataJSON),
          signature: toBase64Url(credential.response.signature),
          userHandle: toBase64Url(credential.response.userHandle),
        };
    return {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      response,
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
    };
  },
  { operation: mode, options: publicKey },
);

/**
 * Open one disposable CTAP2 software authenticator bound to a single browser
 * context, so the SAME credential can register, log in, and authorise across
 * several ceremonies. A fresh authenticator per call cannot do that: the
 * credential would not survive to the next ceremony.
 *
 * This is evidence for a software-passkey trusted-host profile only; it makes no
 * hardware-backed or remote-host custody claim.
 */
export async function openSoftwarePasskeyDevice({
  daemonUrl,
  session,
  webauthnOrigin = "http://localhost:8766",
}) {
  const origin = new URL(webauthnOrigin);
  if (origin.protocol !== "http:" || origin.hostname !== "localhost" || !origin.port) {
    throw new Error("software passkey ceremony requires an explicit localhost HTTP origin");
  }
  const originServer = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    response.end("<!doctype html><title>IOI software passkey ceremony</title>");
  });
  await new Promise((resolve, reject) => {
    originServer.once("error", reject);
    originServer.listen(Number(origin.port), "localhost", resolve);
  });
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(webauthnOrigin);
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    // The session this device presents. `login` replaces it with the one the
    // passkey itself mints, which is what lets a caller drop a password.
    let current = session;
    const request = async (route, body) => {
      const response = await fetch(`${daemonUrl}${route}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(current ? { cookie: `ioi_session=${current}` } : {}),
        },
        body: body == null ? undefined : JSON.stringify(body),
      });
      return { status: response.status, value: await response.json() };
    };

    const device = {
      get session() { return current; },
      async register() {
        const start = await request("/v1/hypervisor/auth/passkeys/register/start", null);
        if (start.status !== 200 || start.value.ok !== true) {
          throw new Error(`software passkey registration start refused: ${start.value.code || start.status}`);
        }
        const credential = await browserCredential(page, "create", normalizePublicKeyOptions(start.value.public_key));
        const finish = await request("/v1/hypervisor/auth/passkeys/register/finish", {
          ceremony_id: start.value.ceremony_id,
          credential,
        });
        if (finish.status !== 200 || finish.value.ok !== true) {
          throw new Error(`software passkey registration finish refused: ${finish.value.code || finish.status}`);
        }
        return finish.value;
      },
      /** Mint a session from the passkey alone. Returns the raw reply so a
       *  caller can assert a REFUSAL as easily as a success. */
      async login({ adopt = true, email } = {}) {
        // Login is email-hinted: the daemon resolves the principal from the
        // address, then the passkey proves it. The address identifies; it does
        // not authenticate, so presenting it is not presenting a credential.
        const start = await request("/v1/hypervisor/auth/passkeys/login/start", { email });
        if (start.status !== 200 || start.value.ok !== true) {
          return { ok: false, stage: "start", status: start.status, code: start.value.code, value: start.value };
        }
        const credential = await browserCredential(page, "get", normalizePublicKeyOptions(start.value.public_key));
        const finish = await request("/v1/hypervisor/auth/passkeys/login/finish", {
          ceremony_id: start.value.ceremony_id,
          credential,
        });
        if (finish.status !== 200 || finish.value.ok !== true) {
          return { ok: false, stage: "finish", status: finish.status, code: finish.value.code, value: finish.value };
        }
        if (adopt && typeof finish.value.session_token === "string") current = finish.value.session_token;
        return { ok: true, ...finish.value };
      },
      async authority(approvalContext, approvalContextHash) {
        const start = await request("/v1/hypervisor/auth/passkeys/authority/start", {
          approval_ceremony_context: approvalContext,
          approval_ceremony_context_hash: approvalContextHash,
        });
        if (start.status !== 200 || start.value.ok !== true) {
          throw new Error(`software passkey authority start refused: ${start.value.code || start.status}`);
        }
        const credential = await browserCredential(page, "get", normalizePublicKeyOptions(start.value.public_key));
        const finish = await request("/v1/hypervisor/auth/passkeys/authority/finish", {
          ceremony_id: start.value.ceremony_id,
          credential,
        });
        if (finish.status !== 200 || finish.value.ok !== true
            || !String(finish.value.receipt_ref || "").startsWith("receipt://auth-factor/")) {
          throw new Error(`software passkey authority finish refused: ${finish.value.code || finish.status}`);
        }
        return finish.value;
      },
      async close() {
        await browser?.close();
        browser = null;
        await new Promise((resolve) => originServer.close(resolve));
      },
    };
    return device;
  } catch (error) {
    await browser?.close();
    await new Promise((resolve) => originServer.close(resolve));
    throw error;
  }
}

/**
 * Exercise the daemon's real WebAuthn registration and exact-context authority ceremony with a
 * disposable CTAP2 software authenticator. This is evidence for a software-passkey trusted-host
 * profile only; it deliberately makes no hardware-backed or remote-host custody claim.
 */
export async function issueSoftwarePasskeyAuthorityFactor({
  daemonUrl,
  session,
  approvalContext,
  approvalContextHash,
  webauthnOrigin = "http://localhost:8766",
}) {
  const device = await openSoftwarePasskeyDevice({ daemonUrl, session, webauthnOrigin });
  try {
    const registered = await device.register();
    const authorized = await device.authority(approvalContext, approvalContextHash);
    return {
      profile: "software_passkey_trusted_host",
      credential_ref: registered.credential_ref,
      enrollment_receipt_ref: registered.receipt_ref,
      authority_receipt_ref: authorized.receipt_ref,
      authority_receipt_hash: authorized.receipt_hash,
    };
  } finally {
    await device.close();
  }
}
