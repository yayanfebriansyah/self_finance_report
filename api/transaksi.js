const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const sql = neon(process.env.DATABASE_URL);
const COOKIE = 'catatan_session';
const AGE = 604800;

// Hard limits: portfolio/demo safety, not a replacement for a paid-plan budget.
const MAX_USERS = 100;
const MAX_TX_PER_USER = 200;
const MAX_TOTAL_TX = 10000;
const MAX_CATS_PER_USER = 30;
const MAX_TOTAL_CATS = 3000;
const MAX_REQ_PER_IP_PER_MIN = 60;
const MAX_WRITE_PER_IP_PER_MIN = 20;
const ipBuckets = new Map();

const json = (r, s, d) => r.status(s).json(d);
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1).trim())]}))}
function user(req){try{return jwt.verify(cookies(req)[COOKIE],process.env.JWT_SECRET)}catch{return null}}
function ip(req){const x=req.headers['x-forwarded-for']||req.headers['x-real-ip']||'';return String(x).split(',')[0].trim()||'unknown'}
function limited(key,limit,windowMs=60000){const now=Date.now();let b=ipBuckets.get(key)||{start:now,count:0};if(now-b.start>=windowMs)b={start:now,count:0};b.count++;ipBuckets.set(key,b);return b.count>limit}
function isWrite(req){return ['POST','PUT','PATCH','DELETE'].includes(req.method)}

module.exports = async (req,res)=>{
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS,POST,PUT,DELETE');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS') return res.status(200).end();

  try{
    if(!process.env.DATABASE_URL)return json(res,500,{error:'DATABASE_URL belum dikonfigurasi di Vercel.'});
    if(!process.env.JWT_SECRET)return json(res,500,{error:'JWT_SECRET belum dikonfigurasi di Vercel.'});

    const clientIp=ip(req);
    if(limited('all:'+clientIp,MAX_REQ_PER_IP_PER_MIN))return json(res,429,{error:'Terlalu banyak permintaan. Coba lagi dalam beberapa saat.'});
    if(isWrite(req)&&limited('write:'+clientIp,MAX_WRITE_PER_IP_PER_MIN))return json(res,429,{error:'Terlalu banyak perubahan dalam waktu singkat. Coba lagi nanti.'});

    const a=req.query?.action;

    if(a==='register'&&req.method==='POST'){
      let {username,password}=req.body||{};
      username=String(username||'').trim();
      if(username.toLowerCase()==='demo')return json(res,400,{error:'Username demo dicadangkan untuk mode demonstrasi.'});
      if(!/^[A-Za-z0-9_.-]{3,50}$/.test(username))return json(res,400,{error:'Username 3-50 karakter: huruf, angka, titik, underscore, minus.'});
      if(typeof password!=='string'||password.length<8)return json(res,400,{error:'Password minimal 8 karakter.'});
      const uc=await sql`SELECT COUNT(*)::int AS n FROM users`;
      if(Number(uc[0].n)>=MAX_USERS)return json(res,429,{error:'Batas jumlah akun demo/portfolio telah tercapai.'});
      if((await sql`SELECT id FROM users WHERE username=${username} LIMIT 1`).length)return json(res,409,{error:'Username sudah digunakan.'});
      const h=await bcrypt.hash(password,12);
      await sql`INSERT INTO users(username,password_hash) VALUES(${username},${h})`;
      return json(res,201,{message:'Akun berhasil dibuat.'});
    }

    if(a==='login'&&req.method==='POST'){
      const {username,password}=req.body||{};
      const q=await sql`SELECT id,username,password_hash FROM users WHERE username=${String(username||'').trim()} LIMIT 1`;
      if(!q.length||!(await bcrypt.compare(String(password||''),q[0].password_hash)))return json(res,401,{error:'Username atau password salah.'});
      const t=jwt.sign({id:q[0].id,username:q[0].username},process.env.JWT_SECRET,{expiresIn:AGE});
      res.setHeader('Set-Cookie',`${COOKIE}=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${AGE}; Secure`);
      return json(res,200,{username:q[0].username});
    }

    if(a==='logout'&&req.method==='POST'){
      res.setHeader('Set-Cookie',`${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`);
      return json(res,200,{message:'Logout berhasil'});
    }

    if(a==='me'&&req.method==='GET'){
      const u=user(req);return u?json(res,200,u):json(res,401,{error:'Belum login'});
    }

    let u=user(req);
    if(!u)return json(res,401,{error:'Sesi tidak valid atau sudah berakhir.'});

    if(a==='change_password'&&req.method==='POST'){
      let {oldPassword,newPassword}=req.body||{};
      if(typeof oldPassword!=='string'||typeof newPassword!=='string'||newPassword.length<8)return json(res,400,{error:'Password baru minimal 8 karakter.'});
      const q=await sql`SELECT password_hash FROM users WHERE id=${u.id} LIMIT 1`;
      if(!q.length||!(await bcrypt.compare(oldPassword,q[0].password_hash)))return json(res,401,{error:'Password lama salah.'});
      if(oldPassword===newPassword)return json(res,400,{error:'Password baru harus berbeda dari password lama.'});
      const h=await bcrypt.hash(newPassword,12);await sql`UPDATE users SET password_hash=${h} WHERE id=${u.id}`;
      return json(res,200,{message:'Password berhasil diganti.'});
    }

    if(a==='categories'&&req.method==='GET'){
      const q=await sql`SELECT jenis,nama FROM kategori WHERE user_id=${u.id} ORDER BY nama ASC`;
      return json(res,200,{pemasukan:q.filter(x=>x.jenis==='pemasukan').map(x=>x.nama),pengeluaran:q.filter(x=>x.jenis==='pengeluaran').map(x=>x.nama)});
    }

    if(a==='add_category'&&req.method==='POST'){
      let {jenis,nama}=req.body||{};nama=String(nama||'').trim();
      if(!['pemasukan','pengeluaran'].includes(jenis)||!/^[^<>]{1,50}$/.test(nama))return json(res,400,{error:'Kategori tidak valid.'});
      const uc=await sql`SELECT COUNT(*)::int AS n FROM kategori WHERE user_id=${u.id}`;
      if(Number(uc[0].n)>=MAX_CATS_PER_USER)return json(res,429,{error:`Maksimal ${MAX_CATS_PER_USER} kategori custom per akun.`});
      const tc=await sql`SELECT COUNT(*)::int AS n FROM kategori`;
      if(Number(tc[0].n)>=MAX_TOTAL_CATS)return json(res,429,{error:'Batas kategori aplikasi telah tercapai.'});
      const exists=await sql`SELECT id FROM kategori WHERE user_id=${u.id} AND jenis=${jenis} AND LOWER(nama)=LOWER(${nama}) LIMIT 1`;
      if(exists.length)return json(res,409,{error:'Kategori sudah ada.'});
      const q=await sql`INSERT INTO kategori(user_id,jenis,nama) VALUES(${u.id},${jenis},${nama}) RETURNING id,nama,jenis`;
      return json(res,201,q[0]);
    }

    if(req.method==='GET'){
      return json(res,200,await sql`SELECT id,tanggal,jenis,kategori,nominal,keterangan FROM transaksi WHERE user_id=${u.id} ORDER BY tanggal DESC,id DESC`);
    }

    if((a==='create'&&req.method==='POST')||(!a&&req.method==='POST')){
      const {tanggal,jenis,kategori,nominal,keterangan=''}=req.body||{};
      const n=Number(nominal),ket=String(keterangan||'').trim();
      if(!tanggal||!kategori||!['pemasukan','pengeluaran'].includes(jenis)||!Number.isSafeInteger(n)||n<=0||n>999999999999999||ket.length>200)return json(res,400,{error:'Data transaksi tidak lengkap, nominal tidak valid, atau keterangan terlalu panjang.'});
      const uc=await sql`SELECT COUNT(*)::int AS n FROM transaksi WHERE user_id=${u.id}`;
      if(Number(uc[0].n)>=MAX_TX_PER_USER)return json(res,429,{error:`Akun dibatasi maksimal ${MAX_TX_PER_USER} transaksi untuk menjaga database demo.`});
      const tc=await sql`SELECT COUNT(*)::int AS n FROM transaksi`;
      if(Number(tc[0].n)>=MAX_TOTAL_TX)return json(res,429,{error:'Batas total transaksi aplikasi telah tercapai untuk keamanan database.'});
      const q=await sql`INSERT INTO transaksi(user_id,tanggal,jenis,kategori,nominal,keterangan) VALUES(${u.id},${tanggal},${jenis},${kategori},${n},${ket}) RETURNING id,tanggal,jenis,kategori,nominal,keterangan`;
      return json(res,201,q[0]);
    }

    if(a==='edit'&&req.method==='POST'){
      const {id,tanggal,jenis,kategori,nominal,keterangan=''}=req.body||{};
      const n=Number(nominal),ket=String(keterangan||'').trim();
      if(!id||!tanggal||!kategori||!['pemasukan','pengeluaran'].includes(jenis)||!Number.isSafeInteger(n)||n<=0||n>999999999999999||ket.length>200)return json(res,400,{error:'Data transaksi tidak valid.'});
      const q=await sql`UPDATE transaksi SET tanggal=${tanggal},jenis=${jenis},kategori=${kategori},nominal=${n},keterangan=${ket} WHERE id=${id} AND user_id=${u.id} RETURNING id,tanggal,jenis,kategori,nominal,keterangan`;
      if(!q.length)return json(res,404,{error:'Transaksi tidak ditemukan.'});return json(res,200,q[0]);
    }

    if(a==='delete_account'&&req.method==='POST'){
      if((req.body||{}).confirmation!=='HAPUS')return json(res,400,{error:'Konfirmasi penghapusan tidak valid.'});
      await sql`DELETE FROM transaksi WHERE user_id=${u.id}`;await sql`DELETE FROM kategori WHERE user_id=${u.id}`;await sql`DELETE FROM users WHERE id=${u.id}`;
      res.setHeader('Set-Cookie',`${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`);return json(res,200,{message:'Akun berhasil dihapus.'});
    }

    if(req.method==='DELETE'){
      const id=req.query?.id;if(id)await sql`DELETE FROM transaksi WHERE id=${id} AND user_id=${u.id}`;else await sql`DELETE FROM transaksi WHERE user_id=${u.id}`;return json(res,200,{message:'Berhasil'});
    }

    return json(res,405,{error:'Method tidak diizinkan'});
  }catch(e){console.error(e);return json(res,500,{error:'Gagal memproses permintaan.',detail:e.message});}
};
