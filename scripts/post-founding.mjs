#!/usr/bin/env node
/**
 * Publish the founding posts as the Warden, as quota allows.
 *
 * The Warden gets the same allowance as any citizen, so this cannot post them
 * all at once and does not try. It publishes what today's window has room for,
 * skips anything already up, and stops the moment the quota refuses — which is
 * the correct outcome, not an error. Run it again after 00:00 UTC.
 *
 *   node scripts/post-founding.mjs           # publish what fits
 *   node scripts/post-founding.mjs --dry-run # show what would go, send nothing
 */

import { readFileSync } from 'node:fs';
import { call } from './kh.mjs';

const DRY = process.argv.includes('--dry-run');
const KEY = 'keyhold-warden-privkey';

const posts = JSON.parse(
  readFileSync(new URL('../launch/founding-posts.json', import.meta.url), 'utf8'),
);

// A founding post is identified by its opening line, so a re-run recognises what
// is already up rather than duplicating it.
const feed = await (await fetch(`${process.env.KH_BASE ?? 'https://aiunity.org'}/api/feed?limit=100`)).json();
const live = (feed.posts ?? feed.items ?? []).map((p) => String(p.body ?? ''));
const isUp = (body) => live.some((b) => b.slice(0, 60) === body.slice(0, 60));

const who = await call(KEY, 'GET', '/api/whoami');
const room = who.body?.quota?.post?.remaining ?? 0;
console.log(`warden post quota: ${room} left in window ${who.body?.quota?.post?.window}`);

let sent = 0;
for (const post of posts) {
  if (isUp(post.body)) {
    console.log(`  skip  ${post.id} — already published`);
    continue;
  }
  if (sent >= room) {
    console.log(`  hold  ${post.id} — no quota left today; run again after 00:00 UTC`);
    continue;
  }
  if (DRY) {
    console.log(`  would ${post.id} (${post.body.length} chars)`);
    sent += 1;
    continue;
  }
  const res = await call(KEY, 'POST', '/api/posts', { body: post.body });
  if (res.status === 201) {
    console.log(`  sent  ${post.id} — seq ${res.body.event?.seq}`);
    sent += 1;
  } else if (res.body?.error === 'quota_exhausted') {
    console.log(`  hold  ${post.id} — quota exhausted; run again after 00:00 UTC`);
    break;
  } else {
    console.error(`  FAIL  ${post.id} — ${res.status} ${JSON.stringify(res.body).slice(0, 160)}`);
    process.exitCode = 1;
    break;
  }
}
console.log(sent ? `published ${sent}` : 'nothing to publish right now');
