
import { PasswordStrength } from './passwordStrength.js'
import { SecurityHelpers } from './securityHelpers.js'

class SecureEncryption {
  constructor() {
    this.mode = 'encrypt'
    this.autoClearTimeout = null
    this.clipboardClearTimeout = null
    this.VERSION = 'v1'
    this.init()
  }

  init() {
    SecurityHelpers.addCachePrevention()
    this.cacheElements()
    this.setupSecurityFeatures()
    this.attachEventListeners()
    this.startInactivityTimer()
  }

  cacheElements() {
    this.modeBtns = document.querySelectorAll('.mode-btn')
    this.inputText = document.getElementById('input-text')
    this.password = document.getElementById('password')
    this.processBtn = document.getElementById('process-btn')
    this.outputSection = document.querySelector('.output-section')
    this.outputText = document.getElementById('output-text')
    this.copyBtn = document.querySelector('.copy-btn')
    this.alert = document.getElementById('alert')
    this.togglePasswordBtn = document.querySelector('.toggle-password')
    this.inputLabel = document.getElementById('input-label')
    this.outputLabel = document.getElementById('output-label')
    this.btnText = document.querySelector('.btn-text')
    this.strengthIndicator = document.getElementById('strength-indicator')
    this.strengthBar = document.getElementById('strength-bar')
    this.strengthText = document.getElementById('strength-text')
    this.strengthFeedback = document.getElementById('strength-feedback')
    this.clearAllBtn = document.getElementById('clear-all-btn')
  }

  setupSecurityFeatures() {
    SecurityHelpers.preventAutocomplete(this.password)
    SecurityHelpers.preventAutocomplete(this.inputText)
    SecurityHelpers.preventAutocomplete(this.outputText)
  }

  attachEventListeners() {
    this.modeBtns.forEach(btn => {
      btn.addEventListener('click', () => this.switchMode(btn.dataset.mode))
    })

    this.processBtn.addEventListener('click', () => this.processText())
    this.copyBtn.addEventListener('click', () => this.copyToClipboard())
    this.togglePasswordBtn.addEventListener('click', () => this.togglePasswordVisibility())
    this.clearAllBtn.addEventListener('click', () => this.clearAllData())

    this.inputText.addEventListener('input', () => {
      this.hideOutput()
      this.resetInactivityTimer()
    })

    this.password.addEventListener('input', () => {
      this.updatePasswordStrength()
      this.hideOutput()
      this.resetInactivityTimer()
    })

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.clearAllData()
      }
    })

    const sensitiveInputs = [this.inputText, this.password, this.outputText]
    sensitiveInputs.forEach(input => {
      input.addEventListener('focus', () => this.resetInactivityTimer())
      input.addEventListener('blur', () => this.resetInactivityTimer())
    })
  }

  updatePasswordStrength() {
    const password = this.password.value
    const evaluation = PasswordStrength.evaluate(password)

    if (!password) {
      this.strengthIndicator.classList.add('hidden')
      return
    }

    this.strengthIndicator.classList.remove('hidden')
    this.strengthBar.style.width = `${evaluation.percentage}%`
    this.strengthBar.className = `strength-bar ${evaluation.strength}`
    this.strengthText.textContent = evaluation.strength.charAt(0).toUpperCase() + evaluation.strength.slice(1)
    this.strengthText.className = `strength-text ${evaluation.strength}`

    if (evaluation.feedback !== 'Strong password') {
      this.strengthFeedback.textContent = evaluation.feedback
      this.strengthFeedback.classList.remove('hidden')
    } else {
      this.strengthFeedback.classList.add('hidden')
    }
  }

  switchMode(newMode) {
    this.mode = newMode
    this.modeBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.mode === newMode)
    })

    if (newMode === 'encrypt') {
      this.inputLabel.textContent = 'Enter text to encrypt'
      this.outputLabel.textContent = 'Encrypted Result'
      this.btnText.textContent = 'Encrypt Text'
      this.inputText.placeholder = 'Type or paste your message here...'
    } else {
      this.inputLabel.textContent = 'Enter encrypted text'
      this.outputLabel.textContent = 'Decrypted Result'
      this.btnText.textContent = 'Decrypt Text'
      this.inputText.placeholder = 'Paste encrypted text here...'
    }

    this.clearAllData()
  }

  hideOutput() {
    this.outputSection.classList.add('hidden')
    this.hideAlert()
  }

  async processText() {
    const text = this.inputText.value.trim()
    const pass = this.password.value

    if (!text) {
      this.showAlert('Please enter some text', 'error')
      return
    }

    if (!pass) {
      this.showAlert('Please enter a password', 'error')
      return
    }

    const passwordEval = PasswordStrength.evaluate(pass)
    if (this.mode === 'encrypt' && !passwordEval.meetsMinimum) {
      this.showAlert(`Password must be at least ${PasswordStrength.MIN_LENGTH} characters for security`, 'warning')
      return
    }

    if (this.mode === 'encrypt' && passwordEval.strength === 'weak') {
      this.showAlert('Warning: Weak password detected. Consider using a stronger password.', 'warning')
    }

    try {
      SecurityHelpers.validateInputLength(text)

      let result
      if (this.mode === 'encrypt') {
        result = await this.encrypt(text, pass)
        this.showAlert('Text encrypted successfully!', 'success')
      } else {
        SecurityHelpers.validateBase64Format(text)
        result = await this.decrypt(text, pass)
        this.showAlert('Text decrypted successfully!', 'success')
      }

      this.outputText.value = result
      this.outputSection.classList.remove('hidden')
      this.resetInactivityTimer()
    } catch (error) {
      const sanitizedMessage = SecurityHelpers.sanitizeErrorMessage(error)
      this.showAlert(sanitizedMessage, 'error')
    }
  }

  async encrypt(text, password) {
    try {
      const encoder = new TextEncoder()
      const data = encoder.encode(text)

      const salt = crypto.getRandomValues(new Uint8Array(16))
      const iv = crypto.getRandomValues(new Uint8Array(12))

      const key = await this.deriveKey(password, salt)

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
      )

      const encryptedArray = new Uint8Array(encrypted)
      const versionByte = new Uint8Array([1])
      const result = new Uint8Array(versionByte.length + salt.length + iv.length + encryptedArray.length)

      result.set(versionByte, 0)
      result.set(salt, 1)
      result.set(iv, 1 + salt.length)
      result.set(encryptedArray, 1 + salt.length + iv.length)

      return this.arrayBufferToBase64(result)
    } catch (error) {
      throw new Error('Encryption failed. Please try again.')
    }
  }

  async decrypt(encryptedText, password) {
    try {
      const encryptedData = this.base64ToArrayBuffer(encryptedText)

      SecurityHelpers.validateEncryptedPayload(encryptedData)

      const version = encryptedData[0]
      if (version !== 1) {
        throw new Error('Unsupported encryption version')
      }

      const salt = encryptedData.slice(1, 17)
      const iv = encryptedData.slice(17, 29)
      const data = encryptedData.slice(29)

      const key = await this.deriveKey(password, salt)

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
      )

      const decoder = new TextDecoder()
      return decoder.decode(decrypted)
    } catch (error) {
      throw new Error('Decryption failed. Check your password and encrypted text.')
    }
  }

  async deriveKey(password, salt) {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    )

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  arrayBufferToBase64(buffer) {
    let binary = ''
    const bytes = new Uint8Array(buffer)
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
  }

  base64ToArrayBuffer(base64) {
    try {
      const binaryString = atob(base64)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }
      return bytes
    } catch (error) {
      throw new Error('Invalid encrypted text format')
    }
  }

  async copyToClipboard() {
    try {
      await navigator.clipboard.writeText(this.outputText.value)
      const originalText = this.copyBtn.innerHTML
      this.copyBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
        Copied!
      `

      if (this.clipboardClearTimeout) {
        clearTimeout(this.clipboardClearTimeout)
      }

      this.clipboardClearTimeout = setTimeout(async () => {
        try {
          await navigator.clipboard.writeText('')
        } catch (e) {
        }
      }, SecurityHelpers.CLIPBOARD_CLEAR_DELAY)

      setTimeout(() => {
        this.copyBtn.innerHTML = originalText
      }, 2000)
    } catch (error) {
      this.showAlert('Failed to copy to clipboard', 'error')
    }
  }

  togglePasswordVisibility() {
    const eyeIcon = this.togglePasswordBtn.querySelector('.eye-icon')
    const eyeOffIcon = this.togglePasswordBtn.querySelector('.eye-off-icon')

    if (this.password.type === 'password') {
      this.password.type = 'text'
      eyeIcon.classList.add('hidden')
      eyeOffIcon.classList.remove('hidden')
    } else {
      this.password.type = 'password'
      eyeIcon.classList.remove('hidden')
      eyeOffIcon.classList.add('hidden')
    }
  }

  clearAllData() {
    SecurityHelpers.secureWipe(this.inputText)
    SecurityHelpers.secureWipe(this.password)
    SecurityHelpers.secureWipe(this.outputText)

    this.hideOutput()
    this.hideAlert()
    this.strengthIndicator.classList.add('hidden')
    this.strengthFeedback.classList.add('hidden')

    if (this.autoClearTimeout) {
      clearTimeout(this.autoClearTimeout)
    }
    if (this.clipboardClearTimeout) {
      clearTimeout(this.clipboardClearTimeout)
    }

    this.showAlert('All data cleared securely', 'success')
  }

  startInactivityTimer() {
    this.autoClearTimeout = setTimeout(() => {
      if (this.inputText.value || this.password.value || this.outputText.value) {
        this.clearAllData()
        this.showAlert('Data cleared after inactivity', 'warning')
      }
    }, SecurityHelpers.AUTO_CLEAR_DELAY)
  }

  resetInactivityTimer() {
    if (this.autoClearTimeout) {
      clearTimeout(this.autoClearTimeout)
    }
    this.startInactivityTimer()
  }

  showAlert(message, type) {
    this.alert.textContent = message
    this.alert.className = `alert ${type}`
    this.alert.classList.remove('hidden')

    setTimeout(() => {
      this.hideAlert()
    }, 5000)
  }

  hideAlert() {
    this.alert.classList.add('hidden')
  }
}

new SecureEncryption()
