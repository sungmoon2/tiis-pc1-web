// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
const { canonical, payloadHash } = require('./canonical');
const contract = require('../contracts/integration-contract.json');
// The 1.1 consumer reads only common envelope fields. It does not invent 1.2
// writer authorization or treat an indexed copy as the peer authority.
const scopeKeys = ['recordId','sourceOrg','targetOrg','recordType','businessIdType','businessId',
  'operation','payloadHash','payloadSizeBytes','payloadStorageType','schemaVersion','submittedAt','transactionId'];
class IntegrityService {
  constructor(pool, reader) { this.pool = pool; this.reader = reader; this.peerUnavailable = false; }
  async peer(recordId) {
    if (this.peerUnavailable) throw new Error('application-injected peer unavailable');
    const bytes = await this.reader.contract.evaluateTransaction('GetEvidence', recordId);
    const row = JSON.parse(Buffer.from(bytes).toString('utf8'));
    if (row.recordId !== recordId || row.schemaVersion !== contract.ledgerSchemaVersion ||
        row.targetOrg !== contract.envelope.targetOrg || !contract.sources[row.sourceOrg])
      throw new Error('consumer envelope not supported');
    return row;
  }
  async inspect(recordId) {
    let peer;
    try { peer = await this.peer(recordId); }
    catch (_) { return { scope:'UNAVAILABLE',payloadProof:'UNAVAILABLE',raw:null,peer:null }; }
    const index = (await this.pool.query('SELECT envelope FROM artifact_index WHERE record_id=$1', [recordId])).rows[0]?.envelope;
    const scope = index && scopeKeys.every(k => index[k] === peer[k]) ? 'VERIFIED' : 'MISMATCH';
    const ref = index?.payloadRef;
    const refValid = typeof ref === 'string' && new RegExp(contract.envelope.payloadRefPattern).test(ref);
    const row = refValid ? (await this.pool.query('SELECT * FROM artifact_payloads WHERE id=$1', [ref.split('/')[1]])).rows[0] : null;
    let proof = 'MISMATCH';
    if (scope === 'VERIFIED' && ref === peer.payloadRef && row) {
      try {
        if (row.record_id === recordId && row.stored_hash === peer.payloadHash &&
            canonical(row.raw) === row.canonical && payloadHash(row.raw) === peer.payloadHash &&
            Buffer.byteLength(row.canonical) === peer.payloadSizeBytes) proof = 'VERIFIED';
      } catch (_) { /* malformed stored payload fails closed */ }
    }
    return { scope,payloadProof:proof,peer,raw:proof === 'VERIFIED' ? row.raw : null };
  }
  async route(access, token, action, recordId) {
    const session = await access.identify(token);
    if (!session) return { status:401,body:{ error:'unauthenticated' } };
    let peer;
    try { peer = await this.peer(recordId); }
    catch (_) { return { status:503,body:{ error:'peer unavailable' } }; }
    const status = access.decision(session,peer,action);
    if (status !== 200) return { status,body:{ error:'forbidden' } };
    if (action === 'detail') {
      const { payloadRef, ...metadata } = peer;
      return { status:200,body:metadata };
    }
    const result = await this.inspect(recordId);
    if (result.scope === 'UNAVAILABLE') return { status:503,body:{ error:'peer unavailable' } };
    // ALLOW is durably written before any protected result (including proof details).
    try { await access.audit(session,action,recordId); }
    catch (_) { return { status:503,body:{ error:'audit unavailable' } }; }
    if (action === 'raw') return result.raw === null ?
      { status:409,body:{ error:'integrity unavailable' } } : { status:200,body:result.raw };
    return { status:200,body:{ scope:result.scope,payloadProof:result.payloadProof } };
  }
}
module.exports = { IntegrityService, scopeKeys };
