/**
 * 
 * 
 */

class RegisterFormValidator {
  /**
   * Email validasyonu
   * @param {string} email 
   * @returns {boolean} 
   */
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * 
   * 
   * @param {string} password
   * @returns {boolean} 
   */
  validatePassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
  }

  /**
   * 
   * 
   * @param {string} username 
   * @returns {boolean}
   */
  validateUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
  }

  /**
   * 
   * 
   * @param {string} fullName 
   * @returns {boolean} 
   */
  validateFullName(fullName) {
    return fullName.trim().length >= 2;
  }

  /**
   * 
   * @param {boolean} termsAccepted 
   * @returns {boolean} 
   */
  validateTermsAccepted(termsAccepted) {
    return termsAccepted === true;
  }

  /**
   * 
   * @param {Object} formData
   * @returns {Object} 
   */
  validateForm(formData) {
    const errors = {};

    if (!this.validateEmail(formData.email)) {
      errors.email = 'Geçerli bir email adresi girin';
    }

    if (!this.validatePassword(formData.password)) {
      errors.password = 'Şifre en az 8 karakter, bir büyük harf, küçük harf ve rakam içermeli';
    }

    if (!this.validateUsername(formData.username)) {
      errors.username = 'Kullanıcı adı 3-20 karakter arasında olmalı';
    }

    if (!this.validateFullName(formData.fullName)) {
      errors.fullName = 'Tam ad en az 2 karakterden oluşmalı';
    }

    if (!this.validateTermsAccepted(formData.termsAccepted)) {
      errors.termsAccepted = 'Şartları kabul etmelisiniz';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors: errors
    };
  }
}

module.exports = RegisterFormValidator;
