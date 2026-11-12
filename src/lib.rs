//! Offline password strength estimation based on pattern detection and entropy.
//!
//! The estimate is intentionally conservative: recognisable structure (common passwords, keyboard walks,
//! sequences, repeats, years) is priced far below random characters, as an attacker's cracking tool would do.

/// A small sample of the most common passwords. Real audits should use a larger breach list.
pub const COMMON: &[&str] = &[
    "password",
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567",
    "qwerty",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "master",
    "welcome",
    "shadow",
    "ashley",
    "bailey",
    "passw0rd",
    "superman",
    "qazwsx",
    "michael",
    "football1",
    "admin",
    "login",
    "princess",
    "starwars",
    "hello",
    "freedom",
    "whatever",
    "qwertyuiop",
    "654321",
    "jordan",
    "harley",
    "hunter",
    "cheese",
    "summer",
    "winter",
    "spring",
    "autumn",
    "secret",
    "changeme",
    "default",
    "guest",
    "root",
    "test",
    "administrator",
    "password1",
    "password123",
    "welcome1",
    "qwerty123",
    "1q2w3e4r",
    "zaq12wsx",
    "000000",
    "121212",
    "mustang",
];

const WALKS: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "qazwsxedcrfv",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Weakness {
    CommonPassword,
    KeyboardWalk,
    Sequence,
    Repeat,
    Year,
    TooShort,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub length: usize,
    pub bits: f64,
    pub score: u8,
    pub weaknesses: Vec<Weakness>,
    pub online_seconds: f64,
    pub offline_seconds: f64,
}

/// Undo common substitutions so `P@ssw0rd` is recognised as `password`.
pub fn normalize_leet(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_ascii_lowercase() {
            '@' | '4' => 'a',
            '3' => 'e',
            '1' | '!' | '|' => 'i',
            '0' => 'o',
            '$' | '5' => 's',
            '7' | '+' => 't',
            other => other,
        })
        .collect()
}

/// True when the password, its leet-normalised form, or either with trailing digits/symbols stripped is a known common password.
pub fn is_common(pw: &str) -> bool {
    let lower = pw.to_lowercase();
    let norm = normalize_leet(pw);
    let strip = |s: &str| s.trim_end_matches(|c: char| !c.is_alphabetic()).to_string();
    [lower.clone(), norm.clone(), strip(&lower), strip(&norm)]
        .iter()
        .any(|v| !v.is_empty() && COMMON.contains(&v.as_str()))
}

fn pool_size(pw: &str) -> f64 {
    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw.chars().any(|c| c.is_ascii_punctuation() || c == ' ') {
        pool += 33;
    }
    if !pw.is_ascii() {
        pool += 100;
    }
    f64::from(pool.max(10))
}

/// Mark character positions covered by structure; returns the coverage mask and the weaknesses found.
fn detect(pw: &str) -> (Vec<bool>, Vec<Weakness>) {
    let chars: Vec<char> = pw.to_lowercase().chars().collect();
    let n = chars.len();
    let mut covered = vec![false; n];
    let mut found: Vec<Weakness> = Vec::new();
    let mut mark = |from: usize, to: usize, w: Weakness, covered: &mut Vec<bool>| {
        for c in covered.iter_mut().take(to).skip(from) {
            *c = true;
        }
        if !found.contains(&w) {
            found.push(w);
        }
    };
    // repeated single character, run of 3 or more
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && chars[j] == chars[i] {
            j += 1;
        }
        if j - i >= 3 {
            mark(i, j, Weakness::Repeat, &mut covered);
        }
        i = j;
    }
    // repeated chunk (abcabc)
    for size in 2..=(n / 2).min(16) {
        for start in 0..=n.saturating_sub(size * 2) {
            if chars[start..start + size] == chars[start + size..start + size * 2] {
                mark(start, start + size * 2, Weakness::Repeat, &mut covered);
            }
        }
    }
    // ascending or descending runs by code point (abcd, 4321)
    let mut i = 0;
    while i + 1 < n {
        let step = chars[i + 1] as i64 - chars[i] as i64;
        if step == 1 || step == -1 {
            let mut j = i + 1;
            while j + 1 < n && chars[j + 1] as i64 - chars[j] as i64 == step {
                j += 1;
            }
            if j - i + 1 >= 4 {
                mark(i, j + 1, Weakness::Sequence, &mut covered);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // keyboard walks, forwards or backwards, 4+ characters
    let text: String = chars.iter().collect();
    for row in WALKS {
        let rev: String = row.chars().rev().collect();
        for pattern in [*row, rev.as_str()] {
            for len in (4..=pattern.len()).rev() {
                for s in 0..=pattern.len() - len {
                    let frag = &pattern[s..s + len];
                    let mut from = 0;
                    while let Some(pos) = text[from..].find(frag) {
                        let byte_pos = from + pos;
                        let ci = text[..byte_pos].chars().count();
                        mark(ci, ci + len, Weakness::KeyboardWalk, &mut covered);
                        from = byte_pos + 1;
                        if from >= text.len() {
                            break;
                        }
                    }
                }
            }
        }
    }
    // years 1900-2099
    for s in 0..n.saturating_sub(3) {
        let w: String = chars[s..s + 4].iter().collect();
        if let Ok(y) = w.parse::<u32>() {
            if (1900..=2099).contains(&y) {
                mark(s, s + 4, Weakness::Year, &mut covered);
            }
        }
    }
    (covered, found)
}

pub fn analyze(pw: &str) -> Report {
    let length = pw.chars().count();
    let (covered, mut weaknesses) = detect(pw);
    let per_char = pool_size(pw).log2();
    let free = covered.iter().filter(|c| !**c).count() as f64;
    let structured = covered.iter().filter(|c| **c).count() as f64;
    let mut bits = free * per_char + structured * 1.5;
    if is_common(pw) {
        weaknesses.insert(0, Weakness::CommonPassword);
        bits = bits.min(10.0 + (length as f64) * 0.5);
    }
    if length < 8 {
        weaknesses.push(Weakness::TooShort);
    }
    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 36.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    };
    let guesses = 2f64.powf(bits) / 2.0;
    Report {
        length,
        bits,
        score,
        weaknesses,
        online_seconds: guesses / 100.0,
        offline_seconds: guesses / 1e10,
    }
}

/// Human readable duration such as "3 hours" or "centuries".
pub fn human_time(seconds: f64) -> String {
    const UNITS: &[(&str, f64)] = &[
        ("second", 1.0),
        ("minute", 60.0),
        ("hour", 3600.0),
        ("day", 86_400.0),
        ("month", 2_629_800.0),
        ("year", 31_557_600.0),
    ];
    if seconds < 1.0 {
        return "instantly".into();
    }
    if seconds >= 31_557_600.0 * 100.0 {
        return "centuries".into();
    }
    let (name, size) = UNITS
        .iter()
        .rev()
        .find(|(_, s)| seconds >= *s)
        .copied()
        .unwrap_or(UNITS[0]);
    let n = (seconds / size).round() as u64;
    format!("{n} {name}{}", if n == 1 { "" } else { "s" })
}
