/**
 * GP-5: Kullanıcı Giriş API (Login) - Backend
 * Express.js ile oturum açma endpoints
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Veritabanı simülasyonu
const users = [
  {
    id: 1,
    email: 'test@example.com',
    username: 'testuser',
    password: '$2b$10$...hashedpassword...'
  }
];

/**
 * POST /api/login
 * Kullanıcı oturum açma
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    // Validasyon
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email ve şifre gerekli'
      });
    }

    // Email format kontrolü
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Geçerli bir email adresi girin'
      });
    }

    // Kullanıcıyı veritabanında ara
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Email veya şifre hatalı'
      });
    }

    // Şifre kontrolü
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Email veya şifre hatalı'
      });
    }

    // JWT token oluştur
    const tokenExpiration = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: tokenExpiration }
    );

    res.json({
      success: true,
      message: 'Giriş başarılı',
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      },
      token,
      expiresIn: tokenExpiration
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası: ' + error.message
    });
  }
});

/**
 * POST /api/logout
 * Oturum kapatma
 */
router.post('/logout', authenticateToken, (req, res) => {
  try {
    // Token'ı blacklist'e ekle (veritabanında saklanabilir)
    res.json({
      success: true,
      message: 'Oturum başarıyla kapatıldı'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası'
    });
  }
});

/**
 * POST /api/verify-token
 * Token geçerliliğini kontrol et
 */
router.post('/verify-token', authenticateToken, (req, res) => {
  try {
    res.json({
      success: true,
      message: 'Token geçerli',
      user: req.user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası'
    });
  }
});

/**
 * POST /api/refresh-token
 * Token yenile
 */
router.post('/refresh-token', authenticateToken, (req, res) => {
  try {
    const user = req.user;

    // Yeni token oluştur
    const newToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Token yenilendi',
      token: newToken
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası'
    });
  }
});

/**
 * Middleware: Token doğrulama
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token gerekli'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Geçersiz token'
      });
    }
    req.user = user;
    next();
  });
}

module.exports = router;
