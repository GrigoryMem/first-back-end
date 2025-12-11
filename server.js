const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Секрет для JWT (для учебного проекта можно хранить прямо в коде)
const JWT_SECRET = 'SECRET_KEY';

// ================== ИНИЦИАЛИЗАЦИЯ БАЗЫ ==================
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP
      );
    `);
    console.log("✅ Таблица users готова");
  } catch (err) {
    console.error("❌ Ошибка при создании таблицы:", err);
    process.exit(1);
  }
}

// ================== МИДЛВЭР ДЛЯ JWT ==================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Нет токена' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Неверный токен' });
  }
}

// ================== РЕГИСТРАЦИЯ ==================
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email и пароль обязательны' });

  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (userCheck.rows.length > 0) return res.status(400).json({ message: 'Такой email уже зарегистрирован' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);

    res.json({ message: 'Регистрация успешна!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ЛОГИН ==================
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: 'Пользователь не найден' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ message: 'Неверный пароль' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== LOGOUT ==================
// Для JWT logout обычно на клиенте — просто удаляется токен.
// Но можно вести список "отозванных" токенов, для учебного проекта можно пропустить.

// ================== ЭНДПОИНТ /ME ==================
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email FROM users WHERE id=$1', [req.user.id]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ЗАБЫЛИ ПАРОЛЬ ==================
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email обязателен' });

  try {
    const token = crypto.randomBytes(20).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 минут

    const result = await pool.query(
      'UPDATE users SET reset_token=$1, reset_token_expiry=$2 WHERE email=$3 RETURNING *',
      [token, expiry, email]
    );

    if (result.rowCount === 0) return res.status(400).json({ message: 'Пользователь не найден' });

    // Здесь для учебного проекта можно просто вернуть токен
    // В реальном проекте нужно отправить на email
    res.json({ message: 'Токен для сброса пароля сгенерирован', resetToken: token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ВОССТАНОВЛЕНИЕ ПАРОЛЯ ==================
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ message: 'Токен и новый пароль обязательны' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE reset_token=$1 AND reset_token_expiry > NOW()',
      [token]
    );

    if (result.rows.length === 0) return res.status(400).json({ message: 'Неверный или истёкший токен' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password=$1, reset_token=NULL, reset_token_expiry=NULL WHERE id=$2',
      [hashedPassword, result.rows[0].id]
    );

    res.json({ message: 'Пароль успешно обновлён' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ПРОВЕРКА СЕРВЕРА ==================
app.get('/', (req, res) => {
  res.send('API работает!');
});

// ================== ЗАПУСК СЕРВЕРА ==================
async function startServer() {
  await initDB();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}
// Для продакшена: такой эндпоинт обычно делают защищённым через JWT. 
//  сделать /users только для админа ?
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

startServer();
