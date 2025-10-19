export class SecurityHelpers {
  static MAX_TEXT_LENGTH = 1000000
  static CLIPBOARD_CLEAR_DELAY = 60000
  static AUTO_CLEAR_DELAY = 300000

  static validateInputLength(text) {
    if (text.length > this.MAX_TEXT_LENGTH) {
      throw new Error('Text is too large. Maximum size is 1MB.')
    }
  }

  static validateBase64Format(text) {
    const base64Regex = /^[A-Za-z0-9+/]+=*$/
    if (!base64Regex.test(text.replace(/\s/g, ''))) {
      throw new Error('Invalid format. Please check your encrypted text.')
    }
  }

  static validateEncryptedPayload(data) {
    if (data.length < 28) {
      throw new Error('Invalid encrypted data format.')
    }
  }

  static secureWipe(element) {
    if (element && element.value) {
      const length = element.value.length
      element.value = 'X'.repeat(length)
      setTimeout(() => {
        element.value = '0'.repeat(length)
        setTimeout(() => {
          element.value = ''
        }, 10)
      }, 10)
    }
  }

  static preventAutocomplete(element) {
    element.setAttribute('autocomplete', 'off')
    element.setAttribute('autocorrect', 'off')
    element.setAttribute('autocapitalize', 'off')
    element.setAttribute('spellcheck', 'false')
  }

  static async scheduleClipboardClear() {
    return new Promise((resolve) => {
      setTimeout(async () => {
        try {
          await navigator.clipboard.writeText('')
          resolve(true)
        } catch (error) {
          resolve(false)
        }
      }, this.CLIPBOARD_CLEAR_DELAY)
    })
  }

  static sanitizeErrorMessage(error) {
    const genericMessages = {
      'decrypt': 'Decryption failed. Please check your password and encrypted text.',
      'encrypt': 'Encryption failed. Please try again.',
      'invalid': 'Invalid input. Please check your data.',
      'default': 'Operation failed. Please try again.'
    }

    const errorStr = error.message.toLowerCase()

    if (errorStr.includes('decrypt')) return genericMessages.decrypt
    if (errorStr.includes('encrypt')) return genericMessages.encrypt
    if (errorStr.includes('invalid')) return genericMessages.invalid

    return genericMessages.default
  }

  static addCachePrevention() {
    const metaTags = [
      { 'http-equiv': 'Cache-Control', content: 'no-cache, no-store, must-revalidate' },
      { 'http-equiv': 'Pragma', content: 'no-cache' },
      { 'http-equiv': 'Expires', content: '0' }
    ]

    metaTags.forEach(attrs => {
      const meta = document.createElement('meta')
      Object.entries(attrs).forEach(([key, value]) => {
        meta.setAttribute(key, value)
      })
      document.head.appendChild(meta)
    })
  }
}
