use passcheck_rs::*;

fn weak(pw: &str, w: Weakness) -> bool {
    analyze(pw).weaknesses.contains(&w)
}

#[test]
fn common_passwords_and_leet_variants_are_caught() {
    for pw in [
        "password",
        "Password1",
        "P@ssw0rd",
        "letmein!!",
        "QWERTY",
        "admin123",
    ] {
        assert!(is_common(pw), "{pw}");
        assert!(analyze(pw).score <= 1, "{pw} scored {}", analyze(pw).score);
    }
    assert!(!is_common("correct horse battery staple"));
    assert!(!is_common("xK9#mQ2$vL7!"));
}

#[test]
fn leet_normalisation() {
    assert_eq!(normalize_leet("P@$$w0rd"), "password");
    assert_eq!(normalize_leet("l33t"), "leet");
}

#[test]
fn keyboard_walks_sequences_repeats_years() {
    assert!(weak("qwertyuiop", Weakness::KeyboardWalk));
    assert!(weak("poiuytrewq", Weakness::KeyboardWalk), "reverse walk");
    assert!(weak("zxcvbn1", Weakness::KeyboardWalk));
    assert!(weak("abcd", Weakness::Sequence));
    assert!(weak("9876xyz", Weakness::Sequence));
    assert!(weak("aaaaaa", Weakness::Repeat));
    assert!(weak("abcabcabc", Weakness::Repeat));
    assert!(weak("sunshine1987", Weakness::Year));
    assert!(!weak("Tr0ub4dor&3", Weakness::Sequence));
}

#[test]
fn structure_is_cheaper_than_randomness_of_the_same_length() {
    let structured = analyze("qwerty123456").bits;
    let random = analyze("kT7#pQ9$vR2!").bits;
    assert!(
        random > structured + 20.0,
        "random {random} vs structured {structured}"
    );
}

#[test]
fn longer_and_more_varied_scores_higher() {
    let scores: Vec<u8> = [
        "abc",
        "tulip",
        "tulip-garden",
        "correct horse battery staple",
        "vR8#kQ2$mL5!xZ9@nB4",
    ]
    .iter()
    .map(|p| analyze(p).score)
    .collect();
    for pair in scores.windows(2) {
        assert!(pair[0] <= pair[1], "scores should not decrease: {scores:?}");
    }
    assert!(scores[0] == 0 && *scores.last().unwrap() >= 3);
}

#[test]
fn passphrases_beat_short_complex_passwords() {
    assert!(analyze("garden violin sunrise pocket marble").bits > analyze("Xk9#mQ2$").bits);
}

#[test]
fn unicode_is_counted_by_characters_not_bytes() {
    assert_eq!(analyze("pässwörd").length, 8);
    assert_eq!(analyze("日本語のパスワード").length, 9);
    assert!(!weak("日本語のパスワード", Weakness::TooShort));
}

#[test]
fn short_passwords_are_flagged() {
    assert!(weak("aB3$", Weakness::TooShort));
    assert!(!weak("aB3$xY7&", Weakness::TooShort));
}

#[test]
fn empty_and_huge_inputs_do_not_panic() {
    let r = analyze("");
    assert_eq!(r.length, 0);
    assert_eq!(r.score, 0);
    let long = "ab".repeat(2000);
    assert!(analyze(&long).bits.is_finite());
}

#[test]
fn time_formatting() {
    assert_eq!(human_time(0.2), "instantly");
    assert_eq!(human_time(90.0), "2 minutes");
    assert_eq!(human_time(3600.0), "1 hour");
    assert_eq!(human_time(86_400.0 * 3.0), "3 days");
    assert_eq!(human_time(1e15), "centuries");
}

#[test]
fn crack_time_orders_online_slower_than_offline() {
    let r = analyze("vR8#kQ2$mL5!");
    assert!(r.online_seconds > r.offline_seconds * 1e7);
}
