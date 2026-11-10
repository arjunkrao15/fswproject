// SecurePass - Password Strength Checker
// All analysis happens inside the browser. The password is never sent or stored.

// ---------- 1. Data used by the checker ----------

// Small local list of commonly used passwords
const commonPasswords = [
  "password", "password1", "password123", "123456", "1234567", "12345678",
  "123456789", "1234567890", "qwerty", "qwerty123", "abc123", "111111",
  "123123", "admin", "admin123", "letmein", "welcome", "welcome1",
  "iloveyou", "monkey", "dragon", "football", "baseball", "master",
  "login", "passw0rd", "p@ssw0rd", "sunshine", "princess", "000000",
  "india123", "test123", "changeme", "secret", "root"
];

// Common keyboard patterns
const keyboardPatterns = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "poiuy"];

// Guessing speed assumed for the cracking time estimate (guesses per second)
const GUESSES_PER_SECOND = 10000000000; // 10 billion (hypothetical)

// ---------- 2. Get elements from the page ----------

const passwordInput = document.getElementById("passwordInput");
const toggleBtn = document.getElementById("toggleBtn");
const analyseBtn = document.getElementById("analyseBtn");
const resetBtn = document.getElementById("resetBtn");

const emptyMessage = document.getElementById("emptyMessage");
const resultsSection = document.getElementById("results");
const commonWarning = document.getElementById("commonWarning");

const strengthBar = document.getElementById("strengthBar");
const strengthLabel = document.getElementById("strengthLabel");
const scoreText = document.getElementById("scoreText");
const checklist = document.getElementById("checklist");

const entropyValue = document.getElementById("entropyValue");
const poolValue = document.getElementById("poolValue");
const lengthValue = document.getElementById("lengthValue");
const crackTime = document.getElementById("crackTime");

// ---------- 3. Helper functions that check the password ----------

function hasUppercase(password) {
  return /[A-Z]/.test(password);
}

function hasLowercase(password) {
  return /[a-z]/.test(password);
}

function hasNumber(password) {
  return /[0-9]/.test(password);
}

function hasSpecialChar(password) {
  // Anything that is not a letter or a number
  return /[^A-Za-z0-9]/.test(password);
}

// Checks for 3 repeated characters (aaa), 3 characters in order (abc, 123, cba)
// and common keyboard patterns (qwerty, asdf)
function hasSequence(password) {
  const text = password.toLowerCase();

  for (let i = 0; i < text.length - 2; i++) {
    const a = text.charCodeAt(i);
    const b = text.charCodeAt(i + 1);
    const c = text.charCodeAt(i + 2);

    // Repeated characters like "aaa" or "111"
    if (a === b && b === c) {
      return true;
    }
    // Increasing like "abc" / "123" or decreasing like "cba" / "321"
    if (b === a + 1 && c === b + 1) {
      return true;
    }
    if (b === a - 1 && c === b - 1) {
      return true;
    }
  }

  // Keyboard patterns
  for (let i = 0; i < keyboardPatterns.length; i++) {
    if (text.includes(keyboardPatterns[i])) {
      return true;
    }
  }

  return false;
}

function isCommonPassword(password) {
  return commonPasswords.includes(password.toLowerCase());
}

// ---------- 4. Strength score ----------

// Score is out of 100:
//   Length:             up to 35  (8+ = 10, 12+ = 10, 16+ = 15)
//   Character types:    up to 40  (10 each for upper, lower, number, special)
//   No sequences:       10
//   Not a common pass:  15
function calculateScore(password) {
  let score = 0;

  // Length points
  if (password.length >= 8) score += 10;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 15;

  // Character variety points
  if (hasUppercase(password)) score += 10;
  if (hasLowercase(password)) score += 10;
  if (hasNumber(password)) score += 10;
  if (hasSpecialChar(password)) score += 10;

  // Pattern points
  if (!hasSequence(password)) score += 10;

  // Common password points
  if (!isCommonPassword(password)) {
    score += 15;
  } else {
    score = Math.min(score, 10); // a common password is always very weak
  }

  return score;
}

// Convert the score into a rating, bar colour and bar width
function getStrengthInfo(score) {
  if (score < 30) {
    return { label: "Very Weak", color: "#ef4444" };   // red
  } else if (score < 50) {
    return { label: "Weak", color: "#f97316" };        // orange
  } else if (score < 70) {
    return { label: "Medium", color: "#facc15" };      // yellow
  } else if (score < 90) {
    return { label: "Strong", color: "#a3e635" };      // light green
  } else {
    return { label: "Very Strong", color: "#22c55e" }; // green
  }
}

// ---------- 5. Entropy and cracking time ----------

// Estimate the size of the character pool (R)
function getPoolSize(password) {
  let pool = 0;
  if (hasLowercase(password)) pool += 26;
  if (hasUppercase(password)) pool += 26;
  if (hasNumber(password)) pool += 10;
  if (hasSpecialChar(password)) pool += 32; // approx. number of symbols on a keyboard
  return pool;
}

// Entropy = L x log2(R)
function calculateEntropy(password) {
  const pool = getPoolSize(password);
  if (pool === 0) return 0;
  return password.length * Math.log2(pool);
}

// Estimated seconds to guess: on average an attacker finds the password
// after trying half of all possible combinations (2^entropy / 2)
function calculateCrackSeconds(entropy) {
  const totalGuesses = Math.pow(2, entropy);
  return totalGuesses / 2 / GUESSES_PER_SECOND;
}

// Convert seconds into readable text
function formatTime(seconds) {
  const minute = 60;
  const hour = 3600;
  const day = 86400;
  const year = 31536000;

  if (seconds < 1) return "Less than a second";
  if (seconds < minute) return "A few seconds";
  if (seconds < hour) return Math.round(seconds / minute) + " minutes";
  if (seconds < day) return Math.round(seconds / hour) + " hours";
  if (seconds < year) return Math.round(seconds / day) + " days";

  const years = seconds / year;
  if (years > 1000000000) return "More than a billion years";
  return Math.round(years).toLocaleString() + " years";
}

// ---------- 6. Showing results on the page ----------

function showChecklist(password) {
  const checks = [
    { text: "At least 8 characters", passed: password.length >= 8 },
    { text: "At least 12 characters", passed: password.length >= 12 },
    { text: "Contains uppercase letters (A-Z)", passed: hasUppercase(password) },
    { text: "Contains lowercase letters (a-z)", passed: hasLowercase(password) },
    { text: "Contains numbers (0-9)", passed: hasNumber(password) },
    { text: "Contains special characters (!, @, #, $ ...)", passed: hasSpecialChar(password) },
    { text: "Does not contain obvious sequences", passed: !hasSequence(password) },
    { text: "Not found in the common password list", passed: !isCommonPassword(password) }
  ];

  checklist.innerHTML = ""; // clear the old checklist

  checks.forEach(function (check) {
    const item = document.createElement("li");
    if (check.passed) {
      item.textContent = "\u2714 " + check.text;  // green tick
      item.className = "pass";
    } else {
      item.textContent = "\u2718 " + check.text;  // red cross
      item.className = "fail";
    }
    checklist.appendChild(item);
  });
}

function showStrength(score) {
  const info = getStrengthInfo(score);
  strengthBar.style.width = score + "%";
  strengthBar.style.backgroundColor = info.color;
  strengthLabel.textContent = info.label;
  strengthLabel.style.color = info.color;
  scoreText.textContent = score;
}

function showEntropyAndTime(password) {
  const entropy = calculateEntropy(password);
  let seconds = calculateCrackSeconds(entropy);

  // Common passwords are found instantly with a dictionary attack
  if (isCommonPassword(password)) {
    seconds = 0;
  }

  entropyValue.textContent = entropy.toFixed(1);
  poolValue.textContent = getPoolSize(password);
  lengthValue.textContent = password.length;
  crackTime.textContent = formatTime(seconds);
}

// ---------- 7. Button actions ----------

function analysePassword() {
  const password = passwordInput.value;

  // Nothing typed
  if (password === "") {
    emptyMessage.hidden = false;
    resultsSection.hidden = true;
    return;
  }

  emptyMessage.hidden = true;
  resultsSection.hidden = false;

  const score = calculateScore(password);

  showStrength(score);
  showChecklist(password);
  showEntropyAndTime(password);

  // Show the warning only for common passwords
  commonWarning.hidden = !isCommonPassword(password);
}

function togglePassword() {
  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    toggleBtn.textContent = "Hide";
  } else {
    passwordInput.type = "password";
    toggleBtn.textContent = "Show";
  }
}

function resetAll() {
  passwordInput.value = "";           // clear the password
  passwordInput.type = "password";
  toggleBtn.textContent = "Show";
  emptyMessage.hidden = true;
  resultsSection.hidden = true;
  commonWarning.hidden = true;
  checklist.innerHTML = "";
  passwordInput.focus();
}

// ---------- 8. Connect buttons to functions ----------

analyseBtn.addEventListener("click", analysePassword);
toggleBtn.addEventListener("click", togglePassword);
resetBtn.addEventListener("click", resetAll);

// Pressing Enter in the input box also analyses the password
passwordInput.addEventListener("keydown", function (event) {
  if (event.key === "Enter") {
    analysePassword();
  }
});
