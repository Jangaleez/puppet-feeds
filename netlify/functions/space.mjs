// Puppet Space pass office.
// Hands out LiveKit access passes and carries out host actions.
// Secrets live in Netlify environment variables, never in the page:
//   LIVEKIT_URL         e.g. wss://your-project.livekit.cloud
//   LIVEKIT_API_KEY
//   LIVEKIT_API_SECRET
//   HOST_PASSWORD       the password hosts type to join as host
import { AccessToken, RoomServiceClient, TokenVerifier, TrackSource } from "livekit-server-sdk";
import { createHash, timingSafeEqual, randomUUID } from "node:crypto";

const ROOM = "puppet-space";
const ROLES = ["host", "cohost", "speaker", "listener"];

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (status, message) => Object.assign(new Error(message), { status });
const sleep = ms => new Promise(r => setTimeout(r, ms));

function settings() {
  const url = process.env.LIVEKIT_URL || "";
  const key = process.env.LIVEKIT_API_KEY || "";
  const secret = process.env.LIVEKIT_API_SECRET || "";
  if (!url || !key || !secret) throw fail(500, "The Space isn't set up yet: the LiveKit settings are missing on Netlify.");
  return { url, key, secret, http: url.replace(/^wss?:\/\//, "https://") };
}

function samePassword(a, b) {
  const h = s => createHash("sha256").update(String(s)).digest();
  return timingSafeEqual(h(a), h(b));
}

// Listeners can only listen and send small data messages (for raising a hand).
// Everyone on stage can publish their microphone, nothing else.
function permissionsFor(role) {
  return role === "listener"
    ? { canSubscribe: true, canPublish: false, canPublishData: true, canPublishSources: [] }
    : { canSubscribe: true, canPublish: true, canPublishData: true, canPublishSources: [TrackSource.MICROPHONE] };
}

function roleOf(participant) {
  try {
    const r = JSON.parse(participant?.metadata || "{}").role;
    return ROLES.includes(r) ? r : "listener";
  } catch { return "listener"; }
}

async function join(body, s) {
  const name = String(body.name || "").trim().slice(0, 40);
  if (!name) throw fail(400, "Enter a name to join.");
  let role = "listener";
  if (body.password) {
    const expected = process.env.HOST_PASSWORD || "";
    if (!expected || !samePassword(body.password, expected)) { await sleep(800); throw fail(403, "That host password isn't right."); }
    role = "host";
  }
  const identity = randomUUID();
  const at = new AccessToken(s.key, s.secret, { identity, name, metadata: JSON.stringify({ role }), ttl: "8h" });
  const grant = { roomJoin: true, room: ROOM, canSubscribe: true, canPublishData: true, canPublish: role !== "listener" };
  if (role !== "listener") grant.canPublishSources = [TrackSource.MICROPHONE];
  at.addGrant(grant);
  return { token: await at.toJwt(), url: s.url, identity, role };
}

// Works out who is asking, from their own pass, and what role the room says they have.
async function whoIsAsking(body, s) {
  let claims;
  try { claims = await new TokenVerifier(s.key, s.secret).verify(String(body.token || "")); }
  catch { throw fail(401, "Your session has expired. Leave and join again."); }
  const svc = new RoomServiceClient(s.http, s.key, s.secret);
  let me;
  try { me = await svc.getParticipant(ROOM, claims.sub); }
  catch { throw fail(403, "You're not in the Space right now."); }
  return { id: claims.sub, role: roleOf(me), svc };
}

async function lookUp(svc, id) {
  try { return await svc.getParticipant(ROOM, String(id || "")); }
  catch { throw fail(404, "That person has already left."); }
}

async function setRole(body, s) {
  const me = await whoIsAsking(body, s);
  const role = String(body.role || "");
  if (!ROLES.includes(role)) throw fail(400, "Unknown role.");
  const target = await lookUp(me.svc, body.target);
  const them = roleOf(target);

  const self = target.identity === me.id;
  const allowed =
    (self && role === "listener") ||                                   // anyone can leave the stage
    (self && me.role === "host" && role === "cohost") ||               // host can step down to co-host
    (!self && me.role === "host" && them !== "host") ||                // host manages everyone but other hosts
    (!self && me.role === "cohost" && ["speaker", "listener"].includes(them) && ["speaker", "listener"].includes(role));
  if (!allowed) throw fail(403, "You don't have permission to do that.");

  await me.svc.updateParticipant(ROOM, target.identity, { metadata: JSON.stringify({ role }), permission: permissionsFor(role) });
  return { ok: true };
}

async function mute(body, s) {
  const me = await whoIsAsking(body, s);
  if (!["host", "cohost"].includes(me.role)) throw fail(403, "Only the host and co-hosts can mute people.");
  const target = await lookUp(me.svc, body.target);
  const them = roleOf(target);
  if (them === "host" || (me.role === "cohost" && them === "cohost")) throw fail(403, "You can't mute that person.");
  const mic = (target.tracks || []).find(t => t.source === TrackSource.MICROPHONE);
  if (mic && !mic.muted) await me.svc.mutePublishedTrack(ROOM, target.identity, mic.sid, true);
  return { ok: true };
}

async function remove(body, s) {
  const me = await whoIsAsking(body, s);
  if (me.role !== "host") throw fail(403, "Only the host can remove people.");
  const target = await lookUp(me.svc, body.target);
  if (roleOf(target) === "host") throw fail(403, "You can't remove another host.");
  await me.svc.removeParticipant(ROOM, target.identity);
  return { ok: true };
}

async function setTitle(body, s) {
  const me = await whoIsAsking(body, s);
  if (!["host", "cohost"].includes(me.role)) throw fail(403, "Only the host and co-hosts can change the title.");
  const title = String(body.title || "").trim().slice(0, 80);
  await me.svc.updateRoomMetadata(ROOM, JSON.stringify({ title }));
  return { ok: true };
}

const ACTIONS = { join, setRole, mute, remove, setTitle };

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);
  try {
    const s = settings();
    const body = await req.json().catch(() => ({}));
    const action = ACTIONS[body.action];
    if (!action) return json({ error: "Unknown action." }, 400);
    return json(await action(body, s));
  } catch (e) {
    return json({ error: e.status ? e.message : "Something went wrong on the server. Try again." }, e.status || 500);
  }
};

export const config = { path: "/api/space" };
