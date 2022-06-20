use bimap::BiMap;
use std::io;

fn main() -> Result<(), io::Error> {
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

fn operation_encrypt(char_map: &BiMap<char, i32>) -> Result<(), io::Error> {
    println!("Enter the word/phrase to encrypt:");

    let mut to_encrypt = String::new();
    io::stdin().read_line(&mut to_encrypt)?;

    println!("Enter a short secret word to use for encryption:");

    let mut secret = String::new();
    io::stdin().read_line(&mut secret)?;

    let result = encrypt(&to_encrypt, &secret, char_map);

    println!("Encrypted: {}", result);

    Ok(())
}

fn operation_decrypt(char_map: &BiMap<char, i32>) -> Result<(), io::Error> {
    println!("Enter the text to decrypt:");

    let mut to_decrypt = String::new();
    io::stdin().read_line(&mut to_decrypt)?;

    println!("Enter the secret word you provided when encrypting:");

    let mut secret = String::new();
    io::stdin().read_line(&mut secret)?;

    let result = decrypt(&to_decrypt, &secret, char_map);

    println!("Decrypted: {}", result);

    Ok(())
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

    struct EncryptTestCase {
        to_encrypt: String,
        secret: String,
        want: String,
    }

    #[test]
    fn test_encrypt() {
        let char_map = build_char_map();

        let test_cases = [
            EncryptTestCase {
                to_encrypt: "attack at dawn".to_string(),
                secret: "lemon".to_string(),
                want: "LXFOPVEFRNHR".to_string(),
            },
            EncryptTestCase {
                to_encrypt: "crypto is short for cryptography".to_string(),
                secret: "abcd".to_string(),
                want: "CSASTPKVSIQUTGQUCSASTPIUAQJB".to_string(),
            },
        ];

        for tc in test_cases {
            let result = encrypt(&tc.to_encrypt, &tc.secret, &char_map);
            assert_eq!(result, tc.want);
        }
    }

    struct DecryptTestCase {
        to_decrypt: String,
        secret: String,
        want: String,
    }

    #[test]
    fn test_decrypt() {
        let char_map = build_char_map();

        let test_cases = [
            DecryptTestCase {
                to_decrypt: "LXFOPVEFRNHR".to_string(),
                secret: "lemon".to_string(),
                want: "ATTACKATDAWN".to_string(),
            },
            DecryptTestCase {
                to_decrypt: "CSASTPKVSIQUTGQUCSASTPIUAQJB".to_string(),
                secret: "abcd".to_string(),
                want: "CRYPTOISSHORTFORCRYPTOGRAPHY".to_string(),
            },
        ];

        for tc in test_cases {
            let result = decrypt(&tc.to_decrypt, &tc.secret, &char_map);
            assert_eq!(result, tc.want);
        }
    }

    struct RepeatTestCase {
        input: String,
        n: usize,
        want: String,
    }

    #[test]
    fn test_repeat() {
        let test_cases = [
            RepeatTestCase {
                input: "hello".to_string(),
                n: 3,
                want: "hel".to_string(),
            },
            RepeatTestCase {
                input: "hello".to_string(),
                n: 5,
                want: "hello".to_string(),
            },
            RepeatTestCase {
                input: "hello".to_string(),
                n: 8,
                want: "hellohel".to_string(),
            },
            RepeatTestCase {
                input: "hello".to_string(),
                n: 10,
                want: "hellohello".to_string(),
            },
        ];

        for tc in test_cases {
            let result = repeat(&tc.input, tc.n);
            assert_eq!(result, tc.want);
        }
    }
}
