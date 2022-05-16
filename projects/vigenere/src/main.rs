use bimap::BiMap;
use std::io;

fn main() {
    let char_map = build_char_map();

    println!("What would you like to do? (e)ncrypt/(d)ecrypt:");

    let mut operation = String::new();
    io::stdin()
        .read_line(&mut operation)
        .expect("Failed to read operation");

    match operation.trim().to_lowercase().as_str() {
        "e" | "encrypt" => operation_encrypt(&char_map),
        "d" | "decrypt" => operation_decrypt(&char_map),
        _ => panic!("Unknown operation provided: {}", operation),
    }
}

fn operation_encrypt(char_map: &BiMap<char, i32>) {
    println!("Enter the word/phrase to encrypt:");

    let mut to_encrypt = String::new();
    io::stdin()
        .read_line(&mut to_encrypt)
        .expect("Failed to read phrase");

    println!("Enter a short secret word to use for encryption:");

    let mut secret = String::new();
    io::stdin()
        .read_line(&mut secret)
        .expect("Failed to read secret word");

    let result = encrypt(&to_encrypt, &secret, char_map);

    println!("Encrypted: {}", result);
}

fn operation_decrypt(char_map: &BiMap<char, i32>) {
    println!("Enter the text to decrypt:");

    let mut to_decrypt = String::new();
    io::stdin()
        .read_line(&mut to_decrypt)
        .expect("Failed to read phrase");

    println!("Enter the secret word you provided when encrypting:");

    let mut secret = String::new();
    io::stdin()
        .read_line(&mut secret)
        .expect("Failed to read secret word");

    let result = decrypt(&to_decrypt, &secret, char_map);

    println!("Decrypted: {}", result);
}

fn encrypt(to_encrypt: &str, secret: &str, char_map: &BiMap<char, i32>) -> String {
    let mut result = String::with_capacity(to_encrypt.len());

    let prepared_to_encrypt = clean_string(to_encrypt);
    let prepared_secret = repeat(&clean_string(&secret), prepared_to_encrypt.len());

    for (i, c) in prepared_secret.chars().enumerate() {
        let current_index = char_map.get_by_left(&c).unwrap();
        let advance_by = char_map
            .get_by_left(&prepared_to_encrypt.chars().nth(i).unwrap())
            .unwrap();
        let encrypted_char = char_map
            .get_by_right(&((current_index + advance_by) % 26))
            .unwrap();
        result.push(*encrypted_char);
    }

    result.to_string()
}

fn decrypt(to_decrypt: &str, secret: &str, char_map: &BiMap<char, i32>) -> String {
    let mut result = String::with_capacity(to_decrypt.len());

    let prepared_to_decrypt = clean_string(to_decrypt);
    let prepared_secret = repeat(&clean_string(&secret), prepared_to_decrypt.len());

    for (i, c) in prepared_secret.chars().enumerate() {
        let current_index = char_map.get_by_left(&c).unwrap();
        let key_index = char_map
            .get_by_left(&prepared_to_decrypt.chars().nth(i).unwrap())
            .unwrap();

        let unescaped_index = key_index - current_index;
        let decrypted_index = match unescaped_index {
            i if i < 0 => unescaped_index + 26,
            _ => unescaped_index,
        };

        let decrypted_char = char_map.get_by_right(&decrypted_index).unwrap();
        result.push(*decrypted_char);
    }

    result.to_string()
}

fn clean_string(s: &str) -> String {
    s.trim().replace(" ", "").to_uppercase()
}

// Repeats a string to a given length.
fn repeat(input: &str, len: usize) -> String {
    if input.len() == len {
        return input.to_string();
    }

    let mut result = input.clone();

    if result.len() < len {
        return repeat(result.repeat(2).as_str(), len);
    }

    assert!(input.len() > len);

    (result, _) = result.split_at(len);

    result.to_string()
}

// Builds a BiMap from uppercase characters to their position in the alphabet.
fn build_char_map() -> BiMap<char, i32> {
    let mut char_map: BiMap<char, i32> = BiMap::new();

    for (i, c) in "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().enumerate() {
        char_map.insert(c, i.try_into().expect("Failed to convert usize to i32"));
    }

    char_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let char_map = build_char_map();

        let test_cases = [
            ("attack at dawn", "lemon", "LXFOPVEFRNHR"),
            (
                "crypto is short for cryptography",
                "abcd",
                "CSASTPKVSIQUTGQUCSASTPIUAQJB",
            ),
        ];

        for tc in test_cases {
            let result = encrypt(tc.0, tc.1, &char_map);
            assert_eq!(result, tc.2);
        }
    }

    #[test]
    fn test_decrypt() {
        let char_map = build_char_map();

        let test_cases = [
            ("LXFOPVEFRNHR", "lemon", "ATTACKATDAWN"),
            (
                "CSASTPKVSIQUTGQUCSASTPIUAQJB",
                "abcd",
                "CRYPTOISSHORTFORCRYPTOGRAPHY",
            ),
        ];

        for tc in test_cases {
            let result = decrypt(tc.0, tc.1, &char_map);
            assert_eq!(result, tc.2);
        }
    }

    #[test]
    fn test_repeat() {
        let test_cases = [
            ("hello", 3, "hel"),
            ("hello", 5, "hello"),
            ("hello", 8, "hellohel"),
            ("hello", 10, "hellohello"),
        ];

        for tc in test_cases {
            let result = repeat(tc.0, tc.1);
            assert_eq!(result, tc.2);
        }
    }
}
