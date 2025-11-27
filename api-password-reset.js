/**
 * GP-6: Şifre Sıfırlama API (Backend)
 * Express.js ile şifre sıfırlama endpoints
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const router = express.Router();

// Veritabanı simülasyonu
const users = [];
const resetTokens = {}; // { token: { userId, expiresAt } }

// Email konfigürasyonu (test amaçlı)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

/**
 * POST /api/password-reset/request
 * Şifre sıfırlama isteği ve email gönder
 */
router.post('/password-reset/request', async (req, res) => {
  try {
    const { email } = req.body;

    // Email validasyonu
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email gerekli'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Geçerli bir email adresi girin'
      });
    }

    // Kullanıcıyı ara
    const user = users.find(u => u.email === email);

    if (!user) {
      // Güvenlik nedeniyle aynı mesaj döndür
      return res.json({
        success: true,
        message: 'Eğer bu email adresiyle kayıtlıysanız, sıfırlama linki email adresinize gönderilecektir'
      });
    }

    // Reset token oluştur
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    resetTokens[hashedToken] = {
      userId: user.id,
      expiresAt: Date.now() + 3600000 // 1 saat
    };

    // Email gönder
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Şifre Sıfırlama Talebiniz',
      html: `
        <p>Merhaba ${user.fullName},</p>
        <p>Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:</p>
        <a href="${resetUrl}">Şifremi Sıfırla</a>
        <p>Bu link 1 saat süreyle geçerlidir.</p>
        <p>Eğer siz bu isteği yapmadıysanız bu emaili görmezden gelin.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({
      success: true,
      message: 'Şifre sıfırlama linki email adresinize gönderildi'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası: ' + error.message
    });
  }
});

/**
 * POST /api/password-reset/validate-token
 * Reset token'ın geçerliliğini kontrol et
 */
router.post('/password-reset/validate-token', (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        isValid: false,
        message: 'Token gerekli'
      });
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    if (!resetTokens[hashedToken]) {
      return res.json({
        success: false,
        isValid: false,
        message: 'Geçersiz veya süresi dolmuş token'
      });
    }

    const tokenData = resetTokens[hashedToken];

    if (Date.now() > tokenData.expiresAt) {
      delete resetTokens[hashedToken];
      return res.json({
        success: false,
        isValid: false,
        message: 'Token süresi dolmuş'
      });
    }

    res.json({
      success: true,
      isValid: true,
      message: 'Token geçerli'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası'
    });
  }
});

/**
 * POST /api/password-reset/confirm
 * Yeni şifre belirle ve sıfırla
 */
router.post('/password-reset/confirm', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Validasyon
    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token ve yeni şifre gerekli'
      });
    }

    // Şifre güvenliği kontrolü
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'Şifre en az 8 karakter, bir büyük harf, küçük harf ve rakam içermeli'
      });
    }

    // Token kontrol
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    if (!resetTokens[hashedToken]) {
      return res.status(400).json({
        success: false,
        message: 'Geçersiz veya süresi dolmuş token'
      });
    }

    const tokenData = resetTokens[hashedToken];

    if (Date.now() > tokenData.expiresAt) {
      delete resetTokens[hashedToken];
      return res.status(400).json({
        success: false,
        message: 'Token süresi dolmuş'
      });
    }

    // Kullanıcıyı bul
    const user = users.find(u => u.id === tokenData.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    // Yeni şifreyi hashle ve güncelle
    const saltRounds = 10;
    user.password = await bcrypt.hash(newPassword, saltRounds);

    // Token'ı sil
    delete resetTokens[hashedToken];

    // Email gönder (bildirim)
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Şifreniz Başarıyla Sıfırlandı',
      html: `
        <p>Merhaba ${user.fullName},</p>
        <p>Şifreniz başarıyla sıfırlanmıştır.</p>
        <p>Yeni şifrenizle giriş yapabilirsiniz.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({
      success: true,
      message: 'Şifreniz başarıyla sıfırlandı. Lütfen yeni şifrenizle giriş yapın.'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası: ' + error.message
    });
  }
});

/**
 * POST /api/password-change
 * Oturum açmış kullanıcı şifre değişikliği (Middlewatre gerekli)
 */
router.post('/password-change', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Validasyon
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Mevcut şifre ve yeni şifre gerekli'
      });
    }

    // Kullanıcıyı bul
    const user = users.find(u => u.id === req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    // Mevcut şifre kontrolü
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Mevcut şifre yanlış'
      });
    }

    // Yeni şifre güvenliği
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'Şifre en az 8 karakter, bir büyük harf, küçük harf ve rakam içermeli'
      });
    }

    // Yeni şifreyi hashle ve güncelle
    const saltRounds = 10;
    user.password = await bcrypt.hash(newPassword, saltRounds);

    res.json({
      success: true,
      message: 'Şifre başarıyla değiştirildi'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası: ' + error.message
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
