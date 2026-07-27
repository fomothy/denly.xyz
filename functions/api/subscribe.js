/**
 * POST /api/subscribe — add a waitlist signup to the Resend audience.
 *
 * This function exists for exactly one reason: the Resend API key must never
 * reach the browser. A form that posted straight to api.resend.com would have
 * to ship the key in the page, and anyone could then read the contact list or
 * send mail as the domain. The key lives in a Cloudflare secret and only this
 * function ever sees it.
 *
 * Contacts in Resend are global — there is one audience per account and no
 * audience ID in the path. Grouping is done with segments, so RESEND_SEGMENT_ID
 * is optional and only tags the signup.
 *
 * Environment (Pages → Settings → Variables and Secrets):
 *   RESEND_API_KEY      required, encrypted
 *   RESEND_SEGMENT_ID   optional, plaintext
 */

const RESEND_CONTACTS_ENDPOINT = "https://api.resend.com/contacts";

// Overridable so the success and duplicate paths can be exercised against a
// local mock — this function only runs in the Workers runtime, so there is no
// other way to test it before deploying. Leave unset in production.
function contactsEndpoint(env) {
  return env.RESEND_CONTACTS_ENDPOINT || RESEND_CONTACTS_ENDPOINT;
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return new Response("Send a POST request with an email address.", {
      status: 405,
      headers: { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  // Redirects must be absolute, and the origin differs between production,
  // *.pages.dev preview deployments, and local wrangler. Derive it from the
  // request rather than hardcoding denly.xyz.
  const origin = new URL(request.url).origin;

  let email = "";
  let honeypot = "";
  let wantsJSON = false;

  const contentType = request.headers.get("content-type") || "";

  try {
    if (contentType.includes("application/json")) {
      const body = await request.json();
      email = String(body.email || "");
      honeypot = String(body.hp_check || "");
      wantsJSON = true;
    } else {
      // A plain <form> post — the no-JavaScript path.
      const form = await request.formData();
      email = String(form.get("email") || "");
      honeypot = String(form.get("hp_check") || "");
    }
  } catch {
    return respond(wantsJSON, origin, 400, "That request could not be read.");
  }

  email = email.trim().toLowerCase();

  // Honeypot: a field hidden from people but filled in by naive bots. Answer
  // with success so the bot has no signal that it was rejected.
  if (honeypot) {
    return respond(wantsJSON, origin, 200, SUCCESS_MESSAGE);
  }

  if (!isPlausibleEmail(email)) {
    return respond(wantsJSON, origin, 400, "That does not look like an email address.");
  }

  if (!env.RESEND_API_KEY) {
    // Misconfiguration, not the visitor's problem. Log loudly, apologise
    // vaguely — never echo config state back to the browser.
    console.error("RESEND_API_KEY is not set; cannot record signup");
    return respond(wantsJSON, origin, 500, "Signups are not working right now.");
  }

  const payload = { email, unsubscribed: false };
  if (env.RESEND_SEGMENT_ID) {
    payload.segments = [{ id: env.RESEND_SEGMENT_ID }];
  }

  let resendResponse;
  try {
    resendResponse = await fetch(contactsEndpoint(env), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("resend request failed", err);
    return respond(wantsJSON, origin, 502, "Could not reach the mailing list. Try again shortly.");
  }

  if (resendResponse.ok) {
    return respond(wantsJSON, origin, 200, SUCCESS_MESSAGE);
  }

  const detail = await resendResponse.text();

  // An address already on the list is a success from the visitor's side.
  // Reporting it differently would also turn this endpoint into an oracle for
  // checking whether a given address has signed up.
  if (isAlreadySubscribed(resendResponse.status, detail)) {
    return respond(wantsJSON, origin, 200, SUCCESS_MESSAGE);
  }

  console.error("resend rejected signup", resendResponse.status, detail);
  return respond(wantsJSON, origin, 502, "Could not add you to the list. Try again shortly.");
}

const SUCCESS_MESSAGE = "You're on the list. You'll hear when there's a release.";

/**
 * Deliberately permissive. Real addresses are far stranger than most regexes
 * allow, and the only authority on deliverability is Resend. This just catches
 * obvious junk before spending an API call on it.
 */
function isPlausibleEmail(value) {
  if (value.length < 3 || value.length > 254) return false;
  if (/\s/.test(value)) return false;
  const at = value.indexOf("@");
  if (at < 1 || at !== value.lastIndexOf("@")) return false;
  const domain = value.slice(at + 1);
  return domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".");
}

function isAlreadySubscribed(status, body) {
  if (status !== 409 && status !== 422) return false;
  return /already|exists|duplicate/i.test(body);
}

/**
 * JSON for fetch callers, a rendered page for plain form posts. The no-JS path
 * has to land somewhere readable — a bare JSON blob in the browser window
 * would look like the site broke.
 */
function respond(wantsJSON, origin, status, message) {
  if (wantsJSON) {
    return new Response(JSON.stringify({ ok: status === 200, message }), {
      status,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    });
  }

  if (status === 200) {
    return Response.redirect(new URL("/thanks", origin).toString(), 303);
  }

  return new Response(errorPage(message), {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function errorPage(message) {
  const safe = String(message).replace(/[<>&]/g, (c) =>
    ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c]
  );
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Something went wrong — Denly</title>
<link rel="icon" type="image/png" href="/denly-fox-512.png">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="hero">
  <div class="wrap">
    <h1>That didn't <em>work</em>.</h1>
    <p class="sub">${safe}</p>
    <div class="hero-cta"><a class="btn" href="/">Back to denly.xyz</a></div>
  </div>
</header>
</body>
</html>`;
}
