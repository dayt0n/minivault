use std::io::{self, Write};

pub fn prompt(line: &str) -> String {
    let mut result = String::new();
    print!("{}: ", line);
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut result).unwrap();
    result.trim().to_string()
}

pub fn prompt_or_get(data: Option<String>, line: &str) -> String {
    if let Some(d) = data {
        return d;
    }
    prompt(line)
}
