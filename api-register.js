/**
 * GP-4: Kullanıcı Kayıt API (Backend)
 * Express.js ile kullanıcı kayıt endpoints
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Veritabanı simülasyonu
const users = [];

/**
 * POST /api/register
 * Yeni kullanıcı kayıt
 */
router.post('/register', async (req, res) => {
  try {
    const { email, username, fullName, password } = req.body;

    // Validasyon
    if (!email || !username || !fullName || !password) {
      return res.status(400).json({
        success: false,
        message: 'Tüm alanlar gerekli'
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

    // Şifre güvenliği kontrolü
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Şifre en az 8 karakter, bir büyük harf, küçük harf ve rakam içermeli'
      });
    }

    // Email'in benzersiz olduğunu kontrol et
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Bu email adresi zaten kayıtlı'
      });
    }

    // Username'in benzersiz olduğunu kontrol et
    const existingUsername = users.find(u => u.username === username);
    if (existingUsername) {
      return res.status(409).json({
        success: false,
        message: 'Bu kullanıcı adı zaten alınmış'
      });
    }

    // Şifreyi hashle
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Yeni kullanıcı oluştur
    const newUser = {
      id: users.length + 1,
      email,
      username,
      fullName,
      password: hashedPassword,
      createdAt: new Date(),
      isEmailVerified: false
    };

    users.push(newUser);

    // JWT token oluştur
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Kayıt başarılı',
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        fullName: newUser.fullName
      },
      token
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası: ' + error.message
    });
  }
});

/**
 * GET /api/users/:id
 * Kullanıcı bilgilerini getir (Auth gerekli)
 */
router.get('/users/:id', authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.id === parseInt(req.params.id));

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        fullName: user.fullName,
        createdAt: user.createdAt
      }
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
