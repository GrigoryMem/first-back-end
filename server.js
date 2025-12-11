const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const USERS_FILE = './users.json';

// загружаем список пользователей
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

// сохраняем пользователей
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// =============== РЕГИСТРАЦИЯ =================
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // простая валидация
  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны' });
  }

  const users = loadUsers();

  // проверяем, существует ли пользователь
  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(400).json({ message: 'Такой email уже зарегистрирован' });
  }

  // хешируем пароль
  const hashedPassword = await bcrypt.hash(password, 10);

  // создаем нового пользователя
  const newUser = {
    id: Date.now(),
    email,
    password: hashedPassword
  };

  users.push(newUser);
  saveUsers(users);

  res.json({ message: 'Регистрация успешна!' });
});

// ==============================================

app.get('/', (req, res) => {
  res.send('API работает!');
});

// запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

//  получение зарег юзеров
app.get('/users', (req, res) => {
  const users = loadUsers(); // загружаем пользователей из файла
  res.json(users);           // отправляем JSON в браузер
});
