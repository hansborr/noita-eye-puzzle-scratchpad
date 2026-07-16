use super::{Direction, MorseRoles};

const MORSE: &[(&str, char)] = &[
    (".-", 'A'),
    ("-...", 'B'),
    ("-.-.", 'C'),
    ("-..", 'D'),
    (".", 'E'),
    ("..-.", 'F'),
    ("--.", 'G'),
    ("....", 'H'),
    ("..", 'I'),
    (".---", 'J'),
    ("-.-", 'K'),
    (".-..", 'L'),
    ("--", 'M'),
    ("-.", 'N'),
    ("---", 'O'),
    (".--.", 'P'),
    ("--.-", 'Q'),
    (".-.", 'R'),
    ("...", 'S'),
    ("-", 'T'),
    ("..-", 'U'),
    ("...-", 'V'),
    (".--", 'W'),
    ("-..-", 'X'),
    ("-.--", 'Y'),
    ("--..", 'Z'),
    ("-----", '0'),
    (".----", '1'),
    ("..---", '2'),
    ("...--", '3'),
    ("....-", '4'),
    (".....", '5'),
    ("-....", '6'),
    ("--...", '7'),
    ("---..", '8'),
    ("----.", '9'),
    (".-.-.-", '.'),
    ("--..--", ','),
    ("..--..", '?'),
    (".----.", '\''),
    ("-.-.--", '!'),
    ("-..-.", '/'),
    ("-.--.", '('),
    ("-.--.-", ')'),
    (".-...", '&'),
    ("---...", ':'),
    ("-.-.-.", ';'),
    ("-...-", '='),
    (".-.-.", '+'),
    ("-....-", '-'),
    ("..--.-", '_'),
    (".-..-.", '"'),
    ("...-..-", '$'),
    (".--.-.", '@'),
];

fn decode_code(code: &str) -> Option<char> {
    MORSE
        .iter()
        .find_map(|&(candidate, ch)| (candidate == code).then_some(ch))
}

fn encode_char(ch: char) -> Option<&'static str> {
    let upper = ch.to_ascii_uppercase();
    MORSE
        .iter()
        .find_map(|&(code, candidate)| (candidate == upper).then_some(code))
}

pub(super) fn decode_words(commands: &[Vec<Direction>], roles: MorseRoles) -> Option<String> {
    let mut plaintext_words = Vec::with_capacity(commands.len());
    for word in commands {
        let mut decoded = String::new();
        let mut code = String::new();
        for &direction in word {
            if direction == roles.separator {
                if code.is_empty() {
                    return None;
                }
                decoded.push(decode_code(&code)?);
                code.clear();
            } else if direction == roles.dot {
                code.push('.');
            } else if direction == roles.dash {
                code.push('-');
            } else {
                return None;
            }
        }
        if code.is_empty() {
            return None;
        }
        decoded.push(decode_code(&code)?);
        plaintext_words.push(decoded);
    }
    Some(plaintext_words.join(" "))
}

pub(super) fn encode_words(text: &str, roles: MorseRoles) -> Option<Vec<Vec<Direction>>> {
    let mut output = Vec::new();
    for word in text.split(' ') {
        if word.is_empty() {
            return None;
        }
        let mut commands = Vec::new();
        for (index, ch) in word.chars().enumerate() {
            if index > 0 {
                commands.push(roles.separator);
            }
            for mark in encode_char(ch)?.chars() {
                commands.push(if mark == '.' { roles.dot } else { roles.dash });
            }
        }
        output.push(commands);
    }
    (!output.is_empty()).then_some(output)
}
