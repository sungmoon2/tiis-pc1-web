// SPDX-FileCopyrightText: 2026 Sungmoon Park
// SPDX-License-Identifier: Apache-2.0
'use strict';
if(process.env.ARTIFACT_MODE!=='synthetic-local')throw new Error('synthetic mode required');
const fs=require('node:fs'),http=require('node:http'),{timingSafeEqual}=require('node:crypto'),{Pool}=require('pg');
const {createClient}=require('@redis/client'),{connectIdentity}=require('./gateway');
const {IntegrityService}=require('./integrity'),{SessionAccess}=require('./access'),{ReadModel}=require('./read-model');
const config=JSON.parse(fs.readFileSync('/work/test-control.json'));
const ids=JSON.parse(fs.readFileSync('/work/identities.json'));
const reader=connectIdentity(ids.reader);
const pool=new Pool({host:'postgres',user:'artifact',database:'artifact',
  password:fs.readFileSync('/work/database-password','utf8'),max:2});
const redis=createClient({url:'redis://redis:6379',socket:{reconnectStrategy:false}});
redis.on('error',error=>console.error(error.message));
const access=new SessionAccess(pool),integrity=new IntegrityService(pool,reader),model=new ReadModel(pool,redis,reader);
async function main() {
  await redis.connect();await access.initialize();await model.initialize();
  const server=http.createServer(async(req,res)=>{
    const send=(status,value)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(value));};
    try {
      if(req.method==='GET' && req.url==='/health')return send(200,{ready:true,pid:process.pid});
      if(req.method==='POST' && req.url==='/test-control') {
        const token=req.headers['x-test-control'];
        if(typeof token!=='string' || token.length!==config.control.length ||
           !timingSafeEqual(Buffer.from(token),Buffer.from(config.control)))return send(403,{error:'test control denied'});
        const chunks=[];let size=0;
        for await(const chunk of req){size+=chunk.length;if(size>4096)return send(413,{error:'too large'});chunks.push(chunk);}
        const command=JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if(command.action==='faults') {
          access.auditUnavailable=command.auditUnavailable===true;
          integrity.peerUnavailable=command.peerUnavailable===true;
          return send(200,{configured:true});
        }
        if(command.action==='sync')return send(200,await model.synchronize());
        if(command.action==='checkpoint')return send(200,{checkpoint:await redis.get('artifact:checkpoint')});
        return send(400,{error:'unknown test action'});
      }
      const match=/^\/records\/([a-f0-9]{24})\/(detail|integrity|raw)$/.exec(req.url);
      if(req.method!=='GET' || !match)return send(404,{error:'not found'});
      const auth=req.headers.authorization;
      const token=typeof auth==='string' && auth.startsWith('Bearer ')?auth.slice(7):null;
      const result=await integrity.route(access,token,match[2],match[1]);
      return send(result.status,result.body);
    }catch(_){return send(503,{error:'service unavailable'});}
  });
  server.listen(8081,'127.0.0.1',()=>console.log('WEB_READY'));
  process.on('SIGTERM',()=>server.close(async()=>{reader.close();await redis.quit();await pool.end();process.exit(0);}));
}
main().catch(error=>{console.error(error.message);process.exit(1);});
