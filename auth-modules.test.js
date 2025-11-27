/**
 * GP-7: Modül Entegrasyon Testleri
 * Jest kullanarak tüm Authentication modülünü test et
 */

const RegisterFormValidator = require('./auth-register');
const LoginFormValidator = require('./auth-login');
const PasswordResetValidator = require('./auth-password-reset');

// GP-1: Kayıt Ekranı Testleri
describe('GP-1: Kayıt Ekranı Form Validasyonları', () => {
  let validator;

  beforeEach(() => {
    validator = new RegisterFormValidator();
  });

  test('Geçerli email doğrulanmalı', () => {
    expect(validator.validateEmail('test@example.com')).toBe(true);
  });

  test('Geçersiz email reddedilmeli', () => {
    expect(validator.validateEmail('invalid-email')).toBe(false);
  });

  test('Güçlü şifre doğrulanmalı', () => {
    expect(validator.validatePassword('SecurePass123')).toBe(true);
  });

  test('Zayıf şifre reddedilmeli', () => {
    expect(validator.validatePassword('weak')).toBe(false);
  });

  test('Geçerli kullanıcı adı doğrulanmalı', () => {
    expect(validator.validateUsername('testuser')).toBe(true);
  });

  test('Kısa kullanıcı adı reddedilmeli', () => {
    expect(validator.validateUsername('ab')).toBe(false);
  });

  test('Geçerli tam ad doğrulanmalı', () => {
    expect(validator.validateFullName('John Doe')).toBe(true);
  });

  test('Boş tam ad reddedilmeli', () => {
    expect(validator.validateFullName('')).toBe(false);
  });

  test('Şartlar kabul edilmeli', () => {
    expect(validator.validateTermsAccepted(true)).toBe(true);
  });

  test('Şartlar kabul edilmemişse reddedilmeli', () => {
    expect(validator.validateTermsAccepted(false)).toBe(false);
  });

  test('Tüm form validasyonu başarılı olmalı', () => {
    const formData = {
      email: 'test@example.com',
      password: 'SecurePass123',
      username: 'testuser',
      fullName: 'John Doe',
      termsAccepted: true
    };
    const result = validator.validateForm(formData);
    expect(result.isValid).toBe(true);
    expect(Object.keys(result.errors).length).toBe(0);
  });

  test('Hatalı form hata mesajı dönmeli', () => {
    const formData = {
      email: 'invalid',
      password: 'weak',
      username: 'ab',
      fullName: '',
      termsAccepted: false
    };
    const result = validator.validateForm(formData);
    expect(result.isValid).toBe(false);
    expect(Object.keys(result.errors).length).toBeGreaterThan(0);
  });
});

// GP-2: Giriş Ekranı Testleri
describe('GP-2: Kullanıcı Giriş Ekranı Validasyonları', () => {
  let validator;

  beforeEach(() => {
    validator = new LoginFormValidator();
  });

  test('Geçerli email doğrulanmalı', () => {
    expect(validator.validateEmail('user@example.com')).toBe(true);
  });

  test('Şifre boş olmamalı', () => {
    expect(validator.validatePassword('password123')).toBe(true);
  });

  test('Boş şifre reddedilmeli', () => {
    expect(validator.validatePassword('')).toBe(false);
  });

  test('Beni Hatırla checkbox doğrulanmalı', () => {
    expect(validator.validateRememberMe(true)).toBe(true);
    expect(validator.validateRememberMe(false)).toBe(true);
  });

  test('Giriş formu tam olarak doğrulanmalı', () => {
    const formData = {
      email: 'user@example.com',
      password: 'password123'
    };
    const result = validator.validateLoginForm(formData);
    expect(result.isValid).toBe(true);
  });

  test('Hatalı giriş formu hata dönmeli', () => {
    const formData = {
      email: 'invalid',
      password: ''
    };
    const result = validator.validateLoginForm(formData);
    expect(result.isValid).toBe(false);
  });

  test('Oturum durumu kontrol edilmeli', () => {
    expect(validator.isLoggedIn()).toBe(false);
  });
});

// GP-3: Şifre Sıfırlama Testleri
describe('GP-3: Şifre Sıfırlama Ekranı Validasyonları', () => {
  let validator;

  beforeEach(() => {
    validator = new PasswordResetValidator();
  });

  test('Email validasyonu yapılmalı', () => {
    expect(validator.validateEmail('reset@example.com')).toBe(true);
  });

  test('Token doğrulanmalı', () => {
    expect(validator.validateToken('validtoken123')).toBe(true);
  });

  test('Boş token reddedilmeli', () => {
    expect(validator.validateToken('')).toBe(false);
  });

  test('Güçlü yeni şifre doğrulanmalı', () => {
    expect(validator.validateNewPassword('NewPass123')).toBe(true);
  });

  test('Zayıf yeni şifre reddedilmeli', () => {
    expect(validator.validateNewPassword('weak')).toBe(false);
  });

  test('Şifreler eşleşmeli', () => {
    expect(validator.validatePasswordMatch('NewPass123', 'NewPass123')).toBe(true);
  });

  test('Şifreler eşleşmemişse reddedilmeli', () => {
    expect(validator.validatePasswordMatch('NewPass123', 'Different123')).toBe(false);
  });

  test('Reset isteği formu doğrulanmalı', () => {
    const formData = {
      email: 'reset@example.com'
    };
    const result = validator.validateResetRequest(formData);
    expect(result.isValid).toBe(true);
  });

  test('Reset formu tam olarak doğrulanmalı', () => {
    const formData = {
      token: 'resettoken123',
      newPassword: 'NewPass123',
      confirmPassword: 'NewPass123'
    };
    const result = validator.validateResetForm(formData);
    expect(result.isValid).toBe(true);
  });
});

// Entegrasyon Testleri
describe('Modül Entegrasyonu', () => {
  test('Kayıt, Giriş ve Şifre Sıfırlama modülleri birlikte çalışmalı', () => {
    const registerValidator = new RegisterFormValidator();
    const loginValidator = new LoginFormValidator();
    const resetValidator = new PasswordResetValidator();

    // Adım 1: Kayıt
    const registrationData = {
      email: 'integration@example.com',
      password: 'SecurePass123',
      username: 'integratoruser',
      fullName: 'Integration Test',
      termsAccepted: true
    };
    const registrationResult = registerValidator.validateForm(registrationData);
    expect(registrationResult.isValid).toBe(true);

    // Adım 2: Giriş
    const loginData = {
      email: 'integration@example.com',
      password: 'SecurePass123'
    };
    const loginResult = loginValidator.validateLoginForm(loginData);
    expect(loginResult.isValid).toBe(true);

    // Adım 3: Şifre Sıfırlama İsteği
    const resetRequestData = {
      email: 'integration@example.com'
    };
    const resetRequestResult = resetValidator.validateResetRequest(resetRequestData);
    expect(resetRequestResult.isValid).toBe(true);

    // Adım 4: Yeni Şifre Belirleme
    const resetData = {
      token: 'mock-reset-token',
      newPassword: 'NewSecurePass456',
      confirmPassword: 'NewSecurePass456'
    };
    const resetResult = resetValidator.validateResetForm(resetData);
    expect(resetResult.isValid).toBe(true);

    // Adım 5: Yeni Şifre ile Giriş
    const newLoginData = {
      email: 'integration@example.com',
      password: 'NewSecurePass456'
    };
    const newLoginResult = loginValidator.validateLoginForm(newLoginData);
    expect(newLoginResult.isValid).toBe(true);
  });

  test('Tüm modüller error handling yapmalı', () => {
    const registerValidator = new RegisterFormValidator();
    const loginValidator = new LoginFormValidator();
    const resetValidator = new PasswordResetValidator();

    // Hatalı kayıt
    const badRegistration = registerValidator.validateForm({
      email: '',
      password: '',
      username: '',
      fullName: '',
      termsAccepted: false
    });
    expect(badRegistration.isValid).toBe(false);

    // Hatalı giriş
    const badLogin = loginValidator.validateLoginForm({
      email: '',
      password: ''
    });
    expect(badLogin.isValid).toBe(false);

    // Hatalı reset
    const badReset = resetValidator.validateResetForm({
      token: '',
      newPassword: 'weak',
      confirmPassword: 'mismatch'
    });
    expect(badReset.isValid).toBe(false);
  });
});

// Performance Testleri
describe('Performance ve Stress Testleri', () => {
  test('Binlerce validation çağrısı hızlı gerçekleşmeli', () => {
    const validator = new RegisterFormValidator();
    const startTime = Date.now();

    for (let i = 0; i < 10000; i++) {
      validator.validateEmail(`user${i}@example.com`);
    }

    const endTime = Date.now();
    const duration = endTime - startTime;

    console.log(`10000 email validasyonu ${duration}ms içinde tamamlandı`);
    expect(duration).toBeLessThan(1000); // 1 saniyeden az
  });
});
