// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
const { common, peer } = require('@hyperledger/fabric-protos');
function decodeBlock(block) {
  const number = Number(block.getHeader().getNumber());
  if (!Number.isSafeInteger(number)) throw new Error('block height outside safe integer');
  const flags = block.getMetadata().getMetadataList()[2];
  const envelopes = block.getData().getDataList();
  if (!flags || flags.length !== envelopes.length) throw new Error('validation metadata absent/misaligned');
  const transactions = []; const records = [];
  for (let i=0;i<envelopes.length;i++) {
    const env = common.Envelope.deserializeBinary(envelopes[i]);
    const payload = common.Payload.deserializeBinary(env.getPayload_asU8());
    const header = common.ChannelHeader.deserializeBinary(payload.getHeader().getChannelHeader_asU8());
    if (header.getType() !== 3) continue;
    const txId = header.getTxId(), valid = flags[i] === 0;
    transactions.push({ txId,valid });
    if (!valid) continue;
    const tx = peer.Transaction.deserializeBinary(payload.getData_asU8());
    for (const action of tx.getActionsList()) {
      const cap = peer.ChaincodeActionPayload.deserializeBinary(action.getPayload_asU8());
      const response = peer.ProposalResponsePayload.deserializeBinary(cap.getAction().getProposalResponsePayload_asU8());
      const cc = peer.ChaincodeAction.deserializeBinary(response.getExtension_asU8());
      const event = peer.ChaincodeEvent.deserializeBinary(cc.getEvents_asU8());
      if (event.getChaincodeId() !== 'evidence' || event.getEventName() !== 'EvidenceCommitted') continue;
      const record = JSON.parse(Buffer.from(event.getPayload_asU8()).toString());
      if (record.transactionId !== txId) throw new Error('event transaction mismatch');
      records.push(record);
    }
  }
  return { number,transactions,records };
}
class ReadModel {
  constructor(pool, redis, reader) { this.pool=pool;this.redis=redis;this.reader=reader;this.pageQueries=0; }
  async initialize() {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS artifact_blocks (number bigint PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS artifact_transactions (
      tx_id text PRIMARY KEY,block_number bigint NOT NULL REFERENCES artifact_blocks(number) ON DELETE CASCADE,
      valid boolean NOT NULL);
      CREATE TABLE IF NOT EXISTS artifact_index (
      record_id text PRIMARY KEY,tx_id text NOT NULL REFERENCES artifact_transactions(tx_id) ON DELETE CASCADE,
      envelope jsonb NOT NULL)`);
  }
  async height() {
    const bytes = await this.reader.network.getContract('qscc').evaluateTransaction('GetChainInfo','artifact');
    const height = Number(common.BlockchainInfo.deserializeBinary(bytes).getHeight());
    if (!Number.isSafeInteger(height) || height < 1) throw new Error('invalid height');
    return height;
  }
  async fetch(number) {
    const events = await this.reader.network.getBlockEvents({ startBlock:BigInt(number) });
    try {
      const first = await events[Symbol.asyncIterator]().next();
      if (first.done) throw new Error('block stream ended');
      const block = decodeBlock(first.value);
      if (block.number !== number) throw new Error('wrong streamed block');
      return block;
    } finally { events.close(); }
  }
  async apply(block, injectRollback=false) {
    const db = await this.pool.connect();
    try {
      await db.query('BEGIN');
      await db.query('INSERT INTO artifact_blocks(number) VALUES($1) ON CONFLICT DO NOTHING', [block.number]);
      for (const tx of block.transactions)
        await db.query(`INSERT INTO artifact_transactions(tx_id,block_number,valid) VALUES($1,$2,$3)
          ON CONFLICT(tx_id) DO NOTHING`, [tx.txId,block.number,tx.valid]);
      for (const r of block.records)
        await db.query(`INSERT INTO artifact_index(record_id,tx_id,envelope) VALUES($1,$2,$3)
          ON CONFLICT(record_id) DO NOTHING`, [r.recordId,r.transactionId,r]);
      if (injectRollback) throw new Error('application-injected projection rollback');
      await db.query('COMMIT');
    } catch (error) { await db.query('ROLLBACK');throw error; }
    finally { db.release(); }
    // Redis is an optimization, never an authoritative completeness assertion.
    const gap = await this.pool.query(`SELECT COALESCE(
      (SELECT min(n)-1 FROM generate_series(0,$1::bigint) n
       LEFT JOIN artifact_blocks b ON b.number=n WHERE b.number IS NULL),$1::bigint) AS last`, [block.number]);
    await this.redis.set('artifact:checkpoint',String(gap.rows[0].last));
  }
  async synchronize() {
    const height = await this.height(); this.pageQueries=0;
    for (;;) {
      this.pageQueries++;
      const gaps = await this.pool.query(`SELECT n FROM generate_series(0,$1::bigint) n
        LEFT JOIN artifact_blocks b ON b.number=n WHERE b.number IS NULL ORDER BY n LIMIT 3`, [height-1]);
      if (!gaps.rows.length) break;
      for (const row of gaps.rows) await this.apply(await this.fetch(Number(row.n)));
    }
    await this.redis.set('artifact:checkpoint',String(height-1));
    const finalized = await this.pool.query(`UPDATE artifact_payloads p SET status='COMMITTED'
      FROM artifact_index i WHERE p.record_id=i.record_id AND p.tx_id=i.tx_id
      AND p.envelope->>'payloadHash'=i.envelope->>'payloadHash'
      AND p.envelope->>'payloadRef'=i.envelope->>'payloadRef'
      AND p.status<>'COMMITTED'`);
    return { height,latest:height-1,pageQueries:this.pageQueries,finalized:finalized.rowCount };
  }
}
module.exports = { ReadModel, decodeBlock };
