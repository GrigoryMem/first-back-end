const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(cors());

// Подключение к PostgreSQL через Render DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // обязательно для Render
});

// ================== АВТОМАТИЧЕСКОЕ СОЗДАНИЕ ТАБЛИЦЫ ==================
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
    console.log("Таблица users готова");
  } catch (err) {
    console.error("Ошибка при создании таблицы:", err);
  }
})();

// ================== РЕГИСТРАЦИЯ ==================
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны' });
  }

  try {
    // Проверяем, есть ли пользователь
    const userCheck = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Такой email уже зарегистрирован' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2)',
      [email, hashedPassword]
    );

    res.json({ message: 'Регистрация успешна!' });
  } catch (err) {
    console.error("Ошибка при регистрации:", err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ПРОВЕРКА СЕРВЕРА ==================
app.get('/', (req, res) => {
  res.send('API работает!');
});

// ================== ВРЕМЕННЫЙ GET /users ==================
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email FROM users');
    res.json(result.rows); // только id и email, пароли не показываем
  } catch (err) {
    console.error("Ошибка при получении пользователей:", err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// ================== ЗАПУСК СЕРВЕРА ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
