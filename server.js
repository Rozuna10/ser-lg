require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 1000 * 60 * 60 * 8;
const INITIAL_ADMIN_EMAIL = (process.env.INITIAL_ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PRINCIPAL_EMAIL = INITIAL_ADMIN_EMAIL || 'lunaluisronaldo@gmail.com';

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 1433,
  database: process.env.DB_NAME || 'SERLG',
  options: {
    encrypt: process.env.DB_ENCRYPT === 'true',
    trustServerCertificate: true
  }
};

let poolPromise;
function getPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(dbConfig).catch((err) => {
      poolPromise = null;
      throw err;
    });
  }
  return poolPromise;
}

const usuarioCache = new Map();
const USUARIO_CACHE_TTL_MS = 15000;

function obtenerUsuarioCache(idUsuario) {
  const item = usuarioCache.get(idUsuario);
  if (!item) return null;
  if (Date.now() > item.exp) {
    usuarioCache.delete(idUsuario);
    return null;
  }
  return item.data;
}

function guardarUsuarioCache(idUsuario, data) {
  usuarioCache.set(idUsuario, {
    data,
    exp: Date.now() + USUARIO_CACHE_TTL_MS
  });
}

function invalidarUsuarioCache(idUsuario) {
  if (idUsuario) {
    usuarioCache.delete(Number(idUsuario));
  } else {
    usuarioCache.clear();
  }
}

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Solo PDF o imágenes (JPG, PNG)'));
  }
});

const loginIntentos = new Map();
const uploadFrecuencia = new Map();
const MAX_INTENTOS = 5;
const VENTANA_MS = 60 * 1000;
const BLOQUEO_MS = 5 * 60 * 1000;
const MAX_SUBIDAS_MIN = 8;

function normalizarTelefono(valor) {
  return String(valor || '').replace(/\D+/g, '').trim();
}

function esAdminPrincipal(usuario) {
  return Boolean(
    usuario &&
    usuario.EsAdmin &&
    String(usuario.Correo || '').trim().toLowerCase() === ADMIN_PRINCIPAL_EMAIL
  );
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verificarPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, originalHash] = storedHash.split(':');
  const derivedHash = crypto.scryptSync(password, salt, 64);
  const originalBuf = Buffer.from(originalHash, 'hex');
  if (derivedHash.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derivedHash, originalBuf);
}

function verificarLimiteLogin(ip) {
  const ahora = Date.now();
  const registro = loginIntentos.get(ip);
  if (!registro) return { permitido: true };

  if (registro.bloqueadoHasta && ahora < registro.bloqueadoHasta) {
    const segRestantes = Math.ceil((registro.bloqueadoHasta - ahora) / 1000);
    return { permitido: false, segRestantes };
  }

  if (ahora - registro.primerIntento > VENTANA_MS && (!registro.bloqueadoHasta || ahora >= registro.bloqueadoHasta)) {
    loginIntentos.delete(ip);
    return { permitido: true };
  }

  return { permitido: true };
}

function registrarFalloLogin(ip) {
  const ahora = Date.now();
  const registro = loginIntentos.get(ip) || { intentos: 0, primerIntento: ahora, bloqueadoHasta: null };

  if (ahora - registro.primerIntento > VENTANA_MS) {
    registro.intentos = 1;
    registro.primerIntento = ahora;
    registro.bloqueadoHasta = null;
  } else {
    registro.intentos += 1;
  }

  if (registro.intentos >= MAX_INTENTOS) {
    registro.bloqueadoHasta = ahora + BLOQUEO_MS;
  }

  loginIntentos.set(ip, registro);
}

function limpiarIntentosLogin(ip) {
  loginIntentos.delete(ip);
}

function verificarLimiteSubida(idUsuario) {
  const ahora = Date.now();
  const lista = (uploadFrecuencia.get(idUsuario) || []).filter((ts) => ahora - ts < 60 * 1000);
  if (lista.length >= MAX_SUBIDAS_MIN) {
    uploadFrecuencia.set(idUsuario, lista);
    return false;
  }
  lista.push(ahora);
  uploadFrecuencia.set(idUsuario, lista);
  return true;
}

function crearToken(payloadObj) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ ...payloadObj, exp })).toString('base64url');
  const firma = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${firma}`;
}

function validarToken(token) {
  if (!token || typeof token !== 'string') return null;
  const partes = token.split('.');
  if (partes.length !== 2) return null;
  const [payload, firma] = partes;
  const firmaEsperada = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');

  const bufA = Buffer.from(firma);
  const bufB = Buffer.from(firmaEsperada);
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) return null;

  try {
    const datos = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!datos.idUsuario || typeof datos.exp !== 'number' || Date.now() >= datos.exp) {
      return null;
    }
    return datos;
  } catch {
    return null;
  }
}

function extraerToken(req) {
  const headerToken = req.headers['x-user-token'];
  if (headerToken) return String(headerToken).trim();
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7).trim();
  return '';
}

async function obtenerUsuarioValidado(idUsuario) {
  const cached = obtenerUsuarioCache(idUsuario);
  if (cached) return cached;

  const pool = await getPool();
  const r = await pool.request()
    .input('IdUsuario', sql.Int, idUsuario)
    .query('SELECT IdUsuario, Nombre, Correo, Telefono, Estado, EsAdmin FROM Usuarios WHERE IdUsuario = @IdUsuario');
  const usuario = r.recordset[0] || null;
  if (usuario) {
    guardarUsuarioCache(idUsuario, usuario);
  }
  return usuario;
}

async function requerirUsuarioActivo(req, res, next) {
  const token = extraerToken(req);
  const datos = validarToken(token);
  if (!datos) {
    return res.status(401).json({ ok: false, error: 'Debe iniciar sesión para continuar' });
  }

  try {
    const usuario = await obtenerUsuarioValidado(datos.idUsuario);
    if (!usuario) {
      return res.status(401).json({ ok: false, error: 'Usuario no encontrado' });
    }
    if (usuario.Estado === 'baneado') {
      return res.status(403).json({
        ok: false,
        error: 'Su cuenta ha sido baneada por subir contenido no permitido o spam'
      });
    }
    req.usuario = usuario;
    next();
  } catch {
    return res.status(500).json({ ok: false, error: 'Error al validar sesión de usuario' });
  }
}

async function requerirAdmin(req, res, next) {
  const token = extraerToken(req);
  const datos = validarToken(token);
  if (!datos) {
    return res.status(401).json({ ok: false, error: 'No autorizado' });
  }

  try {
    const usuario = await obtenerUsuarioValidado(datos.idUsuario);
    if (!usuario || usuario.Estado === 'baneado' || !usuario.EsAdmin) {
      return res.status(403).json({ ok: false, error: 'Acceso restringido a administradores' });
    }
    req.usuario = usuario;
    next();
  } catch {
    return res.status(500).json({ ok: false, error: 'Error al validar permisos de administrador' });
  }
}

function parseIdEntero(valor) {
  if (!/^\d+$/.test(String(valor))) return null;
  const num = parseInt(valor, 10);
  return Number.isSafeInteger(num) && num > 0 ? num : null;
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', requerirAdmin, express.static(uploadDir));

app.post('/api/auth/register', async (req, res) => {
  const nombre = String(req.body?.nombre || '').trim();
  const correo = String(req.body?.correo || '').trim().toLowerCase();
  const telefonoRaw = String(req.body?.telefono || '').trim();
  const telefono = telefonoRaw ? normalizarTelefono(telefonoRaw) : '';
  const password = String(req.body?.password || '');
  const confirmarPassword = String(req.body?.confirmarPassword || '');

  if (nombre.length < 2 || nombre.length > 120) {
    return res.status(400).json({ ok: false, error: 'Ingrese un nombre válido' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo) || correo.length > 150) {
    return res.status(400).json({ ok: false, error: 'Ingrese un correo válido' });
  }
  if (telefonoRaw && (telefono.length < 8 || telefono.length > 15)) {
    return res.status(400).json({ ok: false, error: 'Si captura un número de teléfono, debe tener entre 8 y 15 dígitos' });
  }
  if (password.length < 6) {
    return res.status(400).json({ ok: false, error: 'La contraseña debe tener al menos 6 caracteres' });
  }
  if (password !== confirmarPassword) {
    return res.status(400).json({ ok: false, error: 'Las contraseñas no coinciden' });
  }

  try {
    const pool = await getPool();
    const existe = await pool.request()
      .input('Correo', sql.VarChar(150), correo)
      .input('Telefono', sql.VarChar(20), telefono)
      .query(`
        SELECT IdUsuario, Correo, Telefono
        FROM Usuarios
        WHERE Correo = @Correo
           OR (@Telefono <> '' AND Telefono = @Telefono)
      `);

    if (existe.recordset.length > 0) {
      const duplicado = existe.recordset[0];
      if (String(duplicado.Correo || '').toLowerCase() === correo) {
        return res.status(409).json({ ok: false, error: 'Ese correo ya está registrado' });
      }
      return res.status(409).json({ ok: false, error: 'Ese número de teléfono ya está registrado' });
    }

    const esAdminInicial = INITIAL_ADMIN_EMAIL && correo === INITIAL_ADMIN_EMAIL ? 1 : 0;
    const passwordHash = hashPassword(password);
    const ins = await pool.request()
      .input('Nombre', sql.VarChar(120), nombre)
      .input('Correo', sql.VarChar(150), correo)
      .input('Telefono', sql.VarChar(20), telefono || null)
      .input('PasswordHash', sql.VarChar(255), passwordHash)
      .input('Estado', sql.VarChar(20), 'activo')
      .input('EsAdmin', sql.Bit, esAdminInicial)
      .query(`
        INSERT INTO Usuarios (Nombre, Correo, Telefono, PasswordHash, Estado, EsAdmin)
        OUTPUT INSERTED.IdUsuario, INSERTED.Nombre, INSERTED.Correo, INSERTED.Telefono, INSERTED.Estado, INSERTED.EsAdmin
        VALUES (@Nombre, @Correo, @Telefono, @PasswordHash, @Estado, @EsAdmin)
      `);

    const usuario = ins.recordset[0];
    const esAdmin = Boolean(usuario.EsAdmin);
    const token = crearToken({ idUsuario: usuario.IdUsuario });

    return res.json({
      ok: true,
      token,
      usuario: {
        idUsuario: usuario.IdUsuario,
        nombre: usuario.Nombre,
        correo: usuario.Correo,
        telefono: usuario.Telefono,
        estado: usuario.Estado,
        esAdmin
      },
      aviso: 'Recuerde subir únicamente archivos correspondientes. Si hay algún error o falta información en su papelería, será contactado por su correo o número de teléfono.'
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Error al registrar usuario' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const estadoLimite = verificarLimiteLogin(ip);
  if (!estadoLimite.permitido) {
    return res.status(429).json({
      ok: false,
      error: `Demasiados intentos. Intente de nuevo en ${estadoLimite.segRestantes} segundos`
    });
  }

  const identificador = String(req.body?.identificador || req.body?.correo || '').trim();
  const password = String(req.body?.password || '');

  if (!identificador || !password) {
    registrarFalloLogin(ip);
    return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });
  }

  const esCorreo = identificador.includes('@');
  const correoLimpio = esCorreo ? identificador.toLowerCase() : '';
  const telefonoLimpio = !esCorreo ? normalizarTelefono(identificador) : '';

  if (!correoLimpio && !telefonoLimpio) {
    registrarFalloLogin(ip);
    return res.status(401).json({ ok: false, error: 'Ingrese un correo o número de teléfono válido' });
  }

  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('Correo', sql.VarChar(150), correoLimpio)
      .input('Telefono', sql.VarChar(20), telefonoLimpio)
      .query(`
        SELECT IdUsuario, Nombre, Correo, Telefono, PasswordHash, Estado, EsAdmin
        FROM Usuarios
        WHERE (@Correo <> '' AND Correo = @Correo)
           OR (@Telefono <> '' AND Telefono = @Telefono)
      `);

    const usuario = r.recordset[0];
    if (!usuario || !verificarPassword(password, usuario.PasswordHash)) {
      registrarFalloLogin(ip);
      return res.status(401).json({ ok: false, error: 'Correo/teléfono o contraseña incorrectos' });
    }

    if (usuario.Estado === 'baneado') {
      return res.status(403).json({
        ok: false,
        error: 'Su cuenta está baneada por subir contenido no permitido o spam'
      });
    }

    if (INITIAL_ADMIN_EMAIL && usuario.Correo.toLowerCase() === INITIAL_ADMIN_EMAIL && !usuario.EsAdmin) {
      await pool.request()
        .input('IdUsuario', sql.Int, usuario.IdUsuario)
        .query('UPDATE Usuarios SET EsAdmin = 1 WHERE IdUsuario = @IdUsuario');
      usuario.EsAdmin = true;
    }

    guardarUsuarioCache(usuario.IdUsuario, usuario);
    limpiarIntentosLogin(ip);
    const esAdmin = Boolean(usuario.EsAdmin);
    const token = crearToken({ idUsuario: usuario.IdUsuario });

    return res.json({
      ok: true,
      token,
      usuario: {
        idUsuario: usuario.IdUsuario,
        nombre: usuario.Nombre,
        correo: usuario.Correo,
        telefono: usuario.Telefono,
        estado: usuario.Estado,
        esAdmin
      }
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Error al iniciar sesión' });
  }
});

app.get('/api/mis-expedientes', requerirUsuarioActivo, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('IdUsuario', sql.Int, req.usuario.IdUsuario)
      .input('CorreoUsuario', sql.VarChar(150), req.usuario.Correo)
      .query(`
        SELECT
          c.IdCandidato,
          c.Nombre,
          c.Estatus,
          c.ObservacionAdmin,
          c.ContactoEnviado,
          c.MedioContacto,
          FORMAT(c.FechaContacto, 'dd/MM/yyyy hh:mm tt') AS FechaContactoFormateada,
          FORMAT(c.FechaRegistro, 'dd/MM/yyyy hh:mm tt') AS FechaFormateada,
          d.NombreOriginal,
          COALESCE(u.Correo, d.CorreoUsuario, @CorreoUsuario) AS CorreoContacto,
          u.Telefono AS TelefonoContacto
        FROM Candidatos c
        INNER JOIN Documentos d ON c.IdCandidato = d.IdCandidato
        LEFT JOIN Usuarios u ON d.IdUsuario = u.IdUsuario
        WHERE d.IdUsuario = @IdUsuario OR LOWER(d.CorreoUsuario) = LOWER(@CorreoUsuario)
        ORDER BY c.FechaRegistro DESC
      `);
    res.json(r.recordset);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al consultar sus expedientes' });
  }
});

app.post('/api/candidatos', requerirUsuarioActivo, upload.single('archivoExpediente'), async (req, res) => {
  if (!verificarLimiteSubida(req.usuario.IdUsuario)) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(429).json({ ok: false, error: 'Límite de subidas por minuto alcanzado. Evite hacer spam' });
  }

  if (!req.file) return res.status(400).json({ ok: false, error: 'Archivo requerido' });

  const pool = await getPool().catch(() => null);
  if (!pool) {
    fs.unlink(req.file.path, () => {});
    return res.status(500).json({ ok: false, error: 'Error de conexión a BD' });
  }

  const tx = new sql.Transaction(pool);
  try {
    await tx.begin();
    const nombreGen = 'Expediente - ' + path.basename(req.file.originalname, path.extname(req.file.originalname));

    const r = await new sql.Request(tx)
      .input('Nombre', sql.NVarChar(100), nombreGen)
      .query(`INSERT INTO Candidatos (Nombre) OUTPUT INSERTED.IdCandidato VALUES (@Nombre)`);
    const idCandidato = r.recordset[0].IdCandidato;

    await new sql.Request(tx)
      .input('IdCandidato', sql.Int, idCandidato)
      .input('Tipo', sql.NVarChar(30), 'EXPEDIENTE_FISICO')
      .input('NombreOriginal', sql.NVarChar(255), req.file.originalname)
      .input('NombreArchivo', sql.NVarChar(255), req.file.filename)
      .input('Ruta', sql.NVarChar(500), '/uploads/' + req.file.filename)
      .input('Mime', sql.NVarChar(100), req.file.mimetype)
      .input('IdUsuario', sql.Int, req.usuario.IdUsuario)
      .input('CorreoUsuario', sql.VarChar(150), req.usuario.Correo)
      .query(`
        INSERT INTO Documentos (IdCandidato, TipoDocumento, NombreOriginal, NombreArchivo, RutaArchivo, MimeType, IdUsuario, CorreoUsuario)
        VALUES (@IdCandidato, @Tipo, @NombreOriginal, @NombreArchivo, @Ruta, @Mime, @IdUsuario, @CorreoUsuario)
      `);

    await tx.commit();
    res.json({ ok: true, idCandidato });
  } catch (e) {
    await tx.rollback().catch(() => {});
    fs.unlink(req.file.path, () => {});
    res.status(500).json({ ok: false, error: 'Error al guardar el archivo' });
  }
});

app.get('/api/candidatos', requerirAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request().query(`
      SELECT 
        c.IdCandidato, 
        c.Nombre, 
        c.Estatus, 
        c.ObservacionAdmin,
        c.ContactoEnviado,
        c.MedioContacto,
        FORMAT(c.FechaContacto, 'dd/MM/yyyy hh:mm tt') AS FechaContactoFormateada,
        FORMAT(c.FechaRegistro, 'dd/MM/yyyy hh:mm tt') AS FechaFormateada,
        d.MimeType,
        d.NombreOriginal,
        d.IdUsuario,
        COALESCE(u.Correo, d.CorreoUsuario) AS CorreoUsuario,
        u.Telefono AS TelefonoUsuario,
        u.Nombre AS NombreUsuario,
        COALESCE(u.Estado, 'activo') AS EstadoUsuario
      FROM Candidatos c
      LEFT JOIN Documentos d ON c.IdCandidato = d.IdCandidato
      LEFT JOIN Usuarios u ON d.IdUsuario = u.IdUsuario
      ORDER BY c.FechaRegistro DESC
    `);
    res.json(r.recordset);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al consultar' });
  }
});

app.get('/api/usuarios', requerirAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request().query(`
      SELECT 
        u.IdUsuario,
        u.Nombre,
        u.Correo,
        u.Telefono,
        u.Estado,
        u.EsAdmin,
        COUNT(d.IdDocumento) AS TotalEnvios,
        FORMAT(u.FechaRegistro, 'dd/MM/yyyy hh:mm tt') AS FechaFormateada
      FROM Usuarios u
      LEFT JOIN Documentos d ON d.IdUsuario = u.IdUsuario
      GROUP BY u.IdUsuario, u.Nombre, u.Correo, u.Telefono, u.Estado, u.EsAdmin, u.FechaRegistro
      ORDER BY u.FechaRegistro DESC
    `);
    res.json(r.recordset);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al consultar usuarios' });
  }
});

app.put('/api/usuarios/:id/estado', requerirAdmin, async (req, res) => {
  const idUsuario = parseIdEntero(req.params.id);
  const { estado } = req.body || {};
  const estadosPermitidos = ['activo', 'baneado'];

  if (!idUsuario) {
    return res.status(400).json({ ok: false, error: 'ID de usuario inválido' });
  }
  if (!estadosPermitidos.includes(estado)) {
    return res.status(400).json({ ok: false, error: 'Estado no válido' });
  }
  if (idUsuario === req.usuario.IdUsuario && estado === 'baneado') {
    return res.status(400).json({ ok: false, error: 'No puede banear su propia cuenta activa' });
  }

  try {
    const pool = await getPool();
    const targetRes = await pool.request()
      .input('IdUsuario', sql.Int, idUsuario)
      .query('SELECT IdUsuario, Correo FROM Usuarios WHERE IdUsuario = @IdUsuario');
    const targetUser = targetRes.recordset[0];

    if (!targetUser) {
      return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
    }
    if (String(targetUser.Correo || '').trim().toLowerCase() === ADMIN_PRINCIPAL_EMAIL && estado === 'baneado') {
      return res.status(400).json({ ok: false, error: 'No se puede banear al administrador principal' });
    }

    await pool.request()
      .input('Estado', sql.VarChar(20), estado)
      .input('IdUsuario', sql.Int, idUsuario)
      .query('UPDATE Usuarios SET Estado = @Estado WHERE IdUsuario = @IdUsuario');
    invalidarUsuarioCache(idUsuario);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al actualizar estado del usuario' });
  }
});

app.put('/api/usuarios/:id/admin', requerirAdmin, async (req, res) => {
  if (!esAdminPrincipal(req.usuario)) {
    return res.status(403).json({
      ok: false,
      error: 'Solo el administrador principal puede otorgar o revocar permisos de administrador'
    });
  }

  const idUsuario = parseIdEntero(req.params.id);
  const { esAdmin } = req.body || {};

  if (!idUsuario || typeof esAdmin !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Datos inválidos para actualizar permiso de admin' });
  }
  if (idUsuario === req.usuario.IdUsuario && !esAdmin) {
    return res.status(400).json({ ok: false, error: 'No puede quitarse su propio permiso de administrador' });
  }

  try {
    const pool = await getPool();
    const targetRes = await pool.request()
      .input('IdUsuario', sql.Int, idUsuario)
      .query('SELECT IdUsuario, Correo FROM Usuarios WHERE IdUsuario = @IdUsuario');
    const targetUser = targetRes.recordset[0];

    if (!targetUser) {
      return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
    }
    if (String(targetUser.Correo || '').trim().toLowerCase() === ADMIN_PRINCIPAL_EMAIL && !esAdmin) {
      return res.status(400).json({ ok: false, error: 'No se puede revocar el rol al administrador principal' });
    }

    await pool.request()
      .input('EsAdmin', sql.Bit, esAdmin ? 1 : 0)
      .input('IdUsuario', sql.Int, idUsuario)
      .query('UPDATE Usuarios SET EsAdmin = @EsAdmin WHERE IdUsuario = @IdUsuario');

    invalidarUsuarioCache(idUsuario);
    res.json({ ok: true, esAdmin });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al actualizar permisos de administrador' });
  }
});

app.get('/api/exportar/csv', requerirAdmin, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request().query(`
      SELECT 
        c.IdCandidato, 
        c.Nombre, 
        c.Estatus, 
        c.ObservacionAdmin,
        c.ContactoEnviado,
        c.MedioContacto,
        COALESCE(u.Correo, d.CorreoUsuario) AS CorreoUsuario,
        u.Telefono AS TelefonoUsuario,
        FORMAT(c.FechaRegistro, 'dd/MM/yyyy hh:mm tt') AS FechaFormateada
      FROM Candidatos c
      LEFT JOIN Documentos d ON c.IdCandidato = d.IdCandidato
      LEFT JOIN Usuarios u ON d.IdUsuario = u.IdUsuario
      ORDER BY c.FechaRegistro DESC
    `);

    const escapar = (val) => `"${String(val ?? '').replace(/"/g, '""')}"`;

    let csv = '\uFEFFID,Nombre,Estatus,Observacion,Contactado,Medio,Correo,Telefono,Fecha de Registro\n';
    r.recordset.forEach((row) => {
      csv += [
        escapar(row.IdCandidato),
        escapar(row.Nombre),
        escapar(row.Estatus),
        escapar(row.ObservacionAdmin || ''),
        escapar(row.ContactoEnviado ? 'Sí' : 'No'),
        escapar(row.MedioContacto || ''),
        escapar(row.CorreoUsuario),
        escapar(row.TelefonoUsuario || ''),
        escapar(row.FechaFormateada)
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="Reporte_Expedientes_LogisticsGroup.csv"');
    res.send(csv);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error al generar el reporte');
  }
});

app.put('/api/candidatos/:id/estatus', requerirAdmin, async (req, res) => {
  const idCandidato = parseIdEntero(req.params.id);
  const { estatus } = req.body || {};
  const estatusPermitidos = ['En revisión', 'Aprobado', 'Rechazado'];

  if (!idCandidato) {
    return res.status(400).json({ ok: false, error: 'ID inválido' });
  }
  if (!estatusPermitidos.includes(estatus)) {
    return res.status(400).json({ ok: false, error: 'Estatus no válido' });
  }

  try {
    const pool = await getPool();
    await pool.request()
      .input('Estatus', sql.NVarChar(50), estatus)
      .input('IdCandidato', sql.Int, idCandidato)
      .query('UPDATE Candidatos SET Estatus = @Estatus WHERE IdCandidato = @IdCandidato');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al actualizar el estatus' });
  }
});

app.put('/api/candidatos/:id/observacion', requerirAdmin, async (req, res) => {
  const idCandidato = parseIdEntero(req.params.id);
  const observacion = String(req.body?.observacion || '').trim();

  if (!idCandidato) {
    return res.status(400).json({ ok: false, error: 'ID inválido' });
  }
  if (observacion.length > 500) {
    return res.status(400).json({ ok: false, error: 'La observación no puede superar 500 caracteres' });
  }

  try {
    const pool = await getPool();
    await pool.request()
      .input('ObservacionAdmin', sql.NVarChar(500), observacion || null)
      .input('IdCandidato', sql.Int, idCandidato)
      .query('UPDATE Candidatos SET ObservacionAdmin = @ObservacionAdmin WHERE IdCandidato = @IdCandidato');

    res.json({ ok: true, observacion });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al guardar la observación' });
  }
});

app.put('/api/candidatos/:id/contacto', requerirAdmin, async (req, res) => {
  const idCandidato = parseIdEntero(req.params.id);
  const medio = String(req.body?.medio || '').trim().toLowerCase();
  const mediosPermitidos = ['correo', 'telefono'];

  if (!idCandidato) {
    return res.status(400).json({ ok: false, error: 'ID inválido' });
  }
  if (!mediosPermitidos.includes(medio)) {
    return res.status(400).json({ ok: false, error: 'Medio de contacto no válido' });
  }

  try {
    const pool = await getPool();
    await pool.request()
      .input('MedioContacto', sql.VarChar(20), medio)
      .input('IdCandidato', sql.Int, idCandidato)
      .query(`
        UPDATE Candidatos
        SET ContactoEnviado = 1,
            MedioContacto = @MedioContacto,
            FechaContacto = GETDATE()
        WHERE IdCandidato = @IdCandidato
      `);

    res.json({ ok: true, medio });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al registrar el contacto' });
  }
});

app.get('/api/candidatos/:id/documentos', requerirAdmin, async (req, res) => {
  const idCandidato = parseIdEntero(req.params.id);
  if (!idCandidato) {
    return res.status(400).json({ ok: false, error: 'ID inválido' });
  }

  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('id', sql.Int, idCandidato)
      .query('SELECT TipoDocumento, RutaArchivo, NombreOriginal, MimeType FROM Documentos WHERE IdCandidato=@id');
    res.json(r.recordset);
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Error' });
  }
});

app.delete('/api/candidatos/:id', requerirAdmin, async (req, res) => {
  const idCandidato = parseIdEntero(req.params.id);
  if (!idCandidato) {
    return res.status(400).json({ ok: false, error: 'ID inválido' });
  }

  try {
    const pool = await getPool();

    const docs = await pool.request()
      .input('id', sql.Int, idCandidato)
      .query('SELECT RutaArchivo FROM Documentos WHERE IdCandidato=@id');

    docs.recordset.forEach((doc) => {
      if (!doc.RutaArchivo) return;
      const nombreBase = path.basename(doc.RutaArchivo);
      const rutaFisica = path.resolve(uploadDir, nombreBase);
      if (rutaFisica.startsWith(path.resolve(uploadDir)) && fs.existsSync(rutaFisica)) {
        fs.unlink(rutaFisica, () => {});
      }
    });

    await pool.request()
      .input('id', sql.Int, idCandidato)
      .query('DELETE FROM Candidatos WHERE IdCandidato = @id');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'Error al eliminar el registro' });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    const pool = await getPool();
    await pool.request().query('SELECT 1');
    res.json({ status: 'OK', database: 'Conectado', timestamp: new Date() });
  } catch (e) {
    res.status(500).json({ status: 'ERROR', database: 'Desconectado' });
  }
});

app.use((err, req, res, next) => {
  if (err && err.message && err.message.includes('Solo PDF')) {
    return res.status(400).json({ ok: false, error: err.message });
  }
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ ok: false, error: 'El archivo supera el límite de 10 MB' });
  }
  res.status(500).json({ ok: false, error: 'Error interno del servidor' });
});

app.listen(PORT, () => console.log(`SER-LG corriendo en http://localhost:${PORT}`));