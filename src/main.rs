use passcheck_rs::{analyze, human_time, Report, Weakness};
use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;

const USAGE: &str = "usage: passcheck [--min-score N] [--batch]\n  Reads the password from standard input (never from arguments: those leak into shell history and process lists).\n  --batch   read one password per line; prints only line numbers and verdicts, never the passwords\n  --min-score N   exit 1 if any password scores below N (0-4, default 3)";

fn describe(w: &Weakness) -> &'static str {
    match w {
        Weakness::CommonPassword => "is (or is derived from) a very common password",
        Weakness::KeyboardWalk => "contains a keyboard walk such as qwerty",
        Weakness::Sequence => "contains an alphabetic or numeric sequence",
        Weakness::Repeat => "contains repeated characters or chunks",
        Weakness::Year => "contains a year",
        Weakness::TooShort => "is shorter than 8 characters",
    }
}

fn label(score: u8) -> &'static str {
    ["very weak", "weak", "fair", "strong", "very strong"][score.min(4) as usize]
}

fn main() -> ExitCode {
    let (mut min, mut batch) = (3u8, false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--batch" => batch = true,
            "--min-score" => match args
                .next()
                .and_then(|v| v.parse::<u8>().ok())
                .filter(|v| *v <= 4)
            {
                Some(v) => min = v,
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    let stdin = io::stdin();
    if stdin.is_terminal() && !batch {
        eprintln!("Reading from the terminal. Type the password and press Enter (it will be visible; prefer piping from a password manager).");
    }
    let lines: Vec<String> = stdin.lock().lines().map_while(Result::ok).collect();
    if lines.is_empty() {
        return usage();
    }
    let mut worst = 4u8;
    if batch {
        let mut weak = 0usize;
        for (i, line) in lines.iter().enumerate().filter(|(_, l)| !l.is_empty()) {
            let r = analyze(line);
            worst = worst.min(r.score);
            if r.score < min {
                weak += 1;
            }
            println!(
                "line {:>4}: {} ({} bits, {} chars){}",
                i + 1,
                label(r.score),
                r.bits.round(),
                r.length,
                if r.weaknesses.is_empty() {
                    String::new()
                } else {
                    format!(", {} issue(s)", r.weaknesses.len())
                }
            );
        }
        println!(
            "{} of {} below the minimum score",
            weak,
            lines.iter().filter(|l| !l.is_empty()).count()
        );
    } else {
        let r: Report = analyze(&lines[0]);
        worst = r.score;
        println!(
            "strength: {} (score {}/4, about {} bits, {} characters)",
            label(r.score),
            r.score,
            r.bits.round(),
            r.length
        );
        println!(
            "online attack (100 guesses/s):    {}",
            human_time(r.online_seconds)
        );
        println!(
            "offline attack (10^10 guesses/s): {}",
            human_time(r.offline_seconds)
        );
        for w in &r.weaknesses {
            println!("  - {}", describe(w));
        }
    }
    if worst < min {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
