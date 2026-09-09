// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
function connectIdentity(identity) {
  if (process.env.ARTIFACT_MODE !== 'synthetic-local') throw new Error('synthetic mode required');
  if (!['SourceAMSP','SourceBMSP','TargetTMSP'].includes(identity.mspId)) throw new Error('MSP scope');
  if (!/^peer-[abt]:7051$/.test(identity.endpoint)) throw new Error('isolated endpoint required');
  const short={SourceAMSP:'a',SourceBMSP:'b',TargetTMSP:'t'}[identity.mspId];
  const ca=fs.readFileSync(identity.tlsRootCertificate);
  const client = new grpc.Client(identity.endpoint, grpc.credentials.createSsl(ca), {
    'grpc.ssl_target_name_override':'peer0.'+short+'.artifact.test',
    'grpc.default_authority':'peer0.'+short+'.artifact.test' });
  const gateway = connect({ client, identity: { mspId: identity.mspId,
    credentials: fs.readFileSync(identity.certificate) },
    signer: signers.newPrivateKeySigner(crypto.createPrivateKey(fs.readFileSync(identity.key))),
    evaluateOptions: () => ({ deadline: Date.now() + 20000 }),
    endorseOptions: () => ({ deadline: Date.now() + 20000 }),
    submitOptions: () => ({ deadline: Date.now() + 20000 }),
    commitStatusOptions: () => ({ deadline: Date.now() + 30000 }) });
  const network = gateway.getNetwork('artifact');
  return { client, gateway, network, contract: network.getContract('evidence'),
    close() { gateway.close(); client.close(); } };
}
module.exports = { connectIdentity };
