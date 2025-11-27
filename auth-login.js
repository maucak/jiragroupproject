/**
 * GP-2: Kullanıcı Giriş Ekranı
 * Kullanıcı oturum açma (login) işlevleri
 */

class LoginFormValidator {
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
   * Şifre validasyonu (giriş ekranında minimum kontrol)
   * @param {string} password - Doğrulanacak şifre
   * @returns {boolean} Şifre boş değilse true
   */
  validatePassword(password) {
    return password && password.length > 0;
  }

  /**
   * Beni Hatırla checkbox validasyonu
   * @param {boolean} rememberMe - Beni hatırla durumu
   * @returns {boolean} Her zaman true (isteğe bağlı)
   */
  validateRememberMe(rememberMe) {
    return typeof rememberMe === 'boolean';
  }

  /**
   * Tüm giriş formu validasyonu
   * @param {Object} formData - Form verileri
   * @returns {Object} Doğrulama sonuçları ve hata mesajları
   */
  validateLoginForm(formData) {
    const errors = {};

    if (!this.validateEmail(formData.email)) {
      errors.email = 'Geçerli bir email adresi girin';
    }

    if (!this.validatePassword(formData.password)) {
      errors.password = 'Şifre boş olamaz';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors: errors
    };
  }

  /**
   * Oturum açma isteği gönderme
   * @param {string} email - Kullanıcı email'i
   * @param {string} password - Kullanıcı şifresi
   * @param {boolean} rememberMe - Beni hatırla
   * @returns {Promise} Sunucudan gelen yanıt
   */
  async login(email, password, rememberMe = false) {
    try {
      // Validasyon kontrol
      const validation = this.validateLoginForm({ email, password });
      if (!validation.isValid) {
        return {
          success: false,
          errors: validation.errors
        };
      }

      // Sunucuya POST isteği
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email,
          password,
          rememberMe
        })
      });

      const data = await response.json();

      if (response.ok) {
        // Token'ı localStorage'a kaydet
        if (data.token) {
          localStorage.setItem('authToken', data.token);
          if (rememberMe) {
            localStorage.setItem('rememberMe', 'true');
          }
        }
        return {
          success: true,
          message: 'Giriş başarılı',
          user: data.user
        };
      } else {
        return {
          success: false,
          message: data.message || 'Giriş başarısız'
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
   * Oturum kapatma
   */
  logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('rememberMe');
    return {
      success: true,
      message: 'Oturumunuz kapatıldı'
    };
  }

  /**
   * Token kontrol
   * @returns {string|null} Token varsa döndür, yoksa null
   */
  getAuthToken() {
    return localStorage.getItem('authToken');
  }

  /**
   * Kullanıcı oturum durumunu kontrol et
   * @returns {boolean} Oturum açıksa true
   */
  isLoggedIn() {
    return !!this.getAuthToken();
  }
}

module.exports = LoginFormValidator;
