export class PasswordStrength {
  static MIN_LENGTH = 12
  static RECOMMENDED_LENGTH = 16

  static evaluate(password) {
    if (!password) {
      return {
        score: 0,
        strength: 'none',
        feedback: 'Enter a password',
        percentage: 0
      }
    }

    let score = 0
    const feedback = []

    if (password.length < 8) {
      return {
        score: 0,
        strength: 'very-weak',
        feedback: 'Password is too short (minimum 8 characters)',
        percentage: 10
      }
    }

    score += Math.min(password.length * 2, 40)

    if (/[a-z]/.test(password)) score += 10
    if (/[A-Z]/.test(password)) score += 10
    if (/[0-9]/.test(password)) score += 10
    if (/[^a-zA-Z0-9]/.test(password)) score += 15

    const uniqueChars = new Set(password).size
    score += Math.min(uniqueChars * 2, 15)

    if (this.hasCommonPatterns(password)) {
      score -= 20
      feedback.push('Avoid common patterns')
    }

    if (this.isCommonPassword(password.toLowerCase())) {
      score -= 30
      feedback.push('This is a commonly used password')
    }

    if (password.length < this.MIN_LENGTH) {
      feedback.push(`Use at least ${this.MIN_LENGTH} characters`)
    }

    if (!/[a-z]/.test(password)) feedback.push('Add lowercase letters')
    if (!/[A-Z]/.test(password)) feedback.push('Add uppercase letters')
    if (!/[0-9]/.test(password)) feedback.push('Add numbers')
    if (!/[^a-zA-Z0-9]/.test(password)) feedback.push('Add special characters')

    score = Math.max(0, Math.min(100, score))

    let strength, percentage
    if (score < 30) {
      strength = 'weak'
      percentage = 33
    } else if (score < 60) {
      strength = 'medium'
      percentage = 66
    } else {
      strength = 'strong'
      percentage = 100
    }

    return {
      score,
      strength,
      feedback: feedback.length > 0 ? feedback.join('. ') : 'Strong password',
      percentage,
      meetsMinimum: password.length >= this.MIN_LENGTH
    }
  }

  static hasCommonPatterns(password) {
    const patterns = [
      /^123/,
      /abc/i,
      /qwerty/i,
      /password/i,
      /(.)\1{2,}/,
      /012/,
      /^[a-z]+$/i,
      /^[0-9]+$/
    ]

    return patterns.some(pattern => pattern.test(password))
  }

  static isCommonPassword(password) {
    const common = [
      'password', 'password123', '12345678', 'qwerty', 'abc123',
      'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
      'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
      'bailey', 'passw0rd', 'shadow', '123123', '654321',
      'superman', 'qazwsx', 'michael', 'football', 'welcome'
    ]

    return common.includes(password)
  }
}
