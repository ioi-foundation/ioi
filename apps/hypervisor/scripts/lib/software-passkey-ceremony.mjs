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
    const request = async (route, body) => {
      const response = await fetch(`${daemonUrl}${route}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          cookie: `ioi_session=${session}`,
        },
        body: body == null ? undefined : JSON.stringify(body),
      });
      return { status: response.status, value: await response.json() };
    };

    const registration = await request("/v1/hypervisor/auth/passkeys/register/start", null);
    if (registration.status !== 200 || registration.value.ok !== true) {
      throw new Error(`software passkey registration start refused: ${registration.value.code || registration.status}`);
    }
    const registeredCredential = await browserCredential(
      page,
      "create",
      normalizePublicKeyOptions(registration.value.public_key),
    );
    const registered = await request("/v1/hypervisor/auth/passkeys/register/finish", {
      ceremony_id: registration.value.ceremony_id,
      credential: registeredCredential,
    });
    if (registered.status !== 200 || registered.value.ok !== true) {
      throw new Error(`software passkey registration finish refused: ${registered.value.code || registered.status}`);
    }

    const authority = await request("/v1/hypervisor/auth/passkeys/authority/start", {
      approval_ceremony_context: approvalContext,
      approval_ceremony_context_hash: approvalContextHash,
    });
    if (authority.status !== 200 || authority.value.ok !== true) {
      throw new Error(`software passkey authority start refused: ${authority.value.code || authority.status}`);
    }
    const authorityCredential = await browserCredential(
      page,
      "get",
      normalizePublicKeyOptions(authority.value.public_key),
    );
    const authorized = await request("/v1/hypervisor/auth/passkeys/authority/finish", {
      ceremony_id: authority.value.ceremony_id,
      credential: authorityCredential,
    });
    if (authorized.status !== 200 || authorized.value.ok !== true
        || !String(authorized.value.receipt_ref || "").startsWith("receipt://auth-factor/")) {
      throw new Error(`software passkey authority finish refused: ${authorized.value.code || authorized.status}`);
    }
    return {
      profile: "software_passkey_trusted_host",
      credential_ref: registered.value.credential_ref,
      enrollment_receipt_ref: registered.value.receipt_ref,
      authority_receipt_ref: authorized.value.receipt_ref,
      authority_receipt_hash: authorized.value.receipt_hash,
    };
  } finally {
    await browser?.close();
    await new Promise((resolve) => originServer.close(resolve));
  }
}
