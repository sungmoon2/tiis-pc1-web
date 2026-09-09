// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
const { randomBytes, createHash } = require('node:crypto');
const digest = s => createHash('sha256').update(s).digest('hex');
class SessionAccess {
  constructor(pool) { this.pool = pool; this.auditUnavailable = false; }
  async initialize() {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS artifact_sessions (
      token_hash text PRIMARY KEY, subject text NOT NULL, org text NOT NULL, role text NOT NULL,
      expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false);
      CREATE TABLE IF NOT EXISTS artifact_audit (
      id bigserial PRIMARY KEY, subject text NOT NULL, action text NOT NULL, record_id text NOT NULL,
      decision text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now())`);
  }
  async issue({ subject, org, role }) {
    if (process.env.ARTIFACT_MODE !== 'synthetic-local') throw new Error('synthetic sessions only');
    const token = randomBytes(32).toString('hex');
    await this.pool.query(`INSERT INTO artifact_sessions(token_hash,subject,org,role,expires_at)
      VALUES($1,$2,$3,$4,now()+interval '1 hour')`, [digest(token),subject,org,role]);
    return token;
  }
  async revoke(token) {
    await this.pool.query('UPDATE artifact_sessions SET revoked=true WHERE token_hash=$1', [digest(token)]);
  }
  async identify(token) {
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) return null;
    const result = await this.pool.query(`SELECT subject,org,role FROM artifact_sessions
      WHERE token_hash=$1 AND NOT revoked AND expires_at>now()`, [digest(token)]);
    return result.rows[0] || null;
  }
  decision(session, ledger, action) {
    if (!session) return 401;
    if (!['detail','integrity','raw'].includes(action)) return 404;
    if (!['reader','auditor'].includes(session.role)) return 403;
    if (session.org !== ledger.sourceOrg && session.org !== ledger.targetOrg) return 403;
    if (action === 'raw' && session.role !== 'auditor') return 403;
    return 200;
  }
  async audit(session, action, recordId) {
    if (this.auditUnavailable) throw new Error('application-injected audit unavailable');
    await this.pool.query(`INSERT INTO artifact_audit(subject,action,record_id,decision)
      VALUES($1,$2,$3,'ALLOW')`, [session.subject,action,recordId]);
  }
}
module.exports = { SessionAccess };
