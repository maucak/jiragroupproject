/**
 * GP-3: Şifre Sıfırlama Ekranı
 * Kullanıcı şifre sıfırlama işlevleri
 */

class PasswordResetValidator {
  /**
   * Email validasyonu
   * @param {string} email - Doğrulanacak email adresi
   * @returns {boolean} Email geçerli ise true
   */
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Reset token validasyonu
   * @param {string} token - Reset token'ı
   * @returns {boolean} Token geçerli ise true
   */
  validateToken(token) {
    return token && token.length > 0 && token.length <= 500;
  }

  /**
   * Yeni şifre validasyonu
   * Minimum 8 karakter, en az bir büyük harf, bir küçük harf, bir rakam içermeli
   * @param {string} newPassword - Yeni şifre
   * @returns {boolean} Şifre geçerli ise true
   */
  validateNewPassword(newPassword) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(newPassword);
  }

  /**
   * Şifre tekrarı validasyonu
   * @param {string} newPassword - Yeni şifre
   * @param {string} confirmPassword - Şifre tekrarı
   * @returns {boolean} Şifreler eşleşiyorsa true
   */
  validatePasswordMatch(newPassword, confirmPassword) {
    return newPassword === confirmPassword && newPassword.length > 0;
  }

  /**
   * Adım 1: Şifre Sıfırlama İsteği (Email Gönderme)
   * @param {Object} formData - Form verileri
   * @returns {Object} Doğrulama sonuçları
   */
  validateResetRequest(formData) {
    const errors = {};

    if (!this.validateEmail(formData.email)) {
      errors.email = 'Geçerli bir email adresi girin';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors: errors
    };
  }

  /**
   * Adım 2: Yeni Şifre Belirleme
   * @param {Object} formData - Form verileri (token, newPassword, confirmPassword)
   * @returns {Object} Doğrulama sonuçları
   */
  validateResetForm(formData) {
    const errors = {};

    if (!this.validateToken(formData.token)) {
      errors.token = 'Geçerli bir reset token gerekli';
    }

    if (!this.validateNewPassword(formData.newPassword)) {
      errors.newPassword = 'Şifre en az 8 karakter, bir büyük harf, küçük harf ve rakam içermeli';
    }

    if (!this.validatePasswordMatch(formData.newPassword, formData.confirmPassword)) {
      errors.confirmPassword = 'Şifreler eşleşmiyor';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors: errors
    };
  }

  /**
   * Şifre sıfırlama isteği gönder
   * @param {string} email - Kullanıcı email'i
   * @returns {Promise} Sunucudan gelen yanıt
   */
  async requestPasswordReset(email) {
    try {
      const validation = this.validateResetRequest({ email });
      if (!validation.isValid) {
        return {
          success: false,
          errors: validation.errors
        };
      }

      const response = await fetch('/api/password-reset/request', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await response.json();

      if (response.ok) {
        return {
          success: true,
          message: 'Şifre sıfırlama linki email adresinize gönderildi'
        };
      } else {
        return {
          success: false,
          message: data.message || 'İstek başarısız'
        };
      }
    } catch (error) {
      return {
        success: false,
        message: 'Bir hata oluştu: ' + error.message
      };
    }
  }

  /**
   * Yeni şifre belirle
   * @param {string} token - Reset token'ı
   * @param {string} newPassword - Yeni şifre
   * @param {string} confirmPassword - Şifre tekrarı
   * @returns {Promise} Sunucudan gelen yanıt
   */
  async resetPassword(token, newPassword, confirmPassword) {
    try {
      const validation = this.validateResetForm({
        token,
        newPassword,
        confirmPassword
      });

      if (!validation.isValid) {
        return {
          success: false,
          errors: validation.errors
        };
      }

      const response = await fetch('/api/password-reset/confirm', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          token,
          newPassword
        })
      });

      const data = await response.json();

      if (response.ok) {
        return {
          success: true,
          message: 'Şifreniz başarıyla sıfırlandı. Lütfen yeni şifrenizle giriş yapın.'
        };
      } else {
        return {
          success: false,
          message: data.message || 'Şifre sıfırlama başarısız'
        };
      }
    } catch (error) {
      return {
        success: false,
        message: 'Bir hata oluştu: ' + error.message
      };
    }
  }

  /**
   * Token geçerliliğini kontrol et
   * @param {string} token - Kontrol edilecek token
   * @returns {Promise} Token geçerli mi?
   */
  async validateResetToken(token) {
    try {
      const response = await fetch('/api/password-reset/validate-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token })
      });

      const data = await response.json();
      return {
        isValid: data.isValid,
        message: data.message
      };
    } catch (error) {
      return {
        isValid: false,
        message: 'Token kontrol hatası: ' + error.message
      };
    }
  }
}

module.exports = PasswordResetValidator;
