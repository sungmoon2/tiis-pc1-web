// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
const { createHash } = require('node:crypto');
// Independent implementation for JSON values. Object keys use UTF-16 lexical
// ordering, not locale ordering. Serialize entries directly, including "10"/"2".
function canonical(value, active = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (typeof value !== 'object') throw new TypeError('outside canonical JSON domain');
  if (active.has(value)) throw new TypeError('cyclic JSON');
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) throw new TypeError('non-JSON object');
  active.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + Array.from(value, item => canonical(item === undefined ? null : item, active)).join(',') + ']';
    }
    return '{' + Object.keys(value).filter(key => value[key] !== undefined).sort()
      .map(key => JSON.stringify(key) + ':' + canonical(value[key], active)).join(',') + '}';
  } finally { active.delete(value); }
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const payloadHash = value => 'sha256:' + sha(canonical(value));
module.exports = { canonical, sha, payloadHash };
