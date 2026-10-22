//! Password generator, the same as in the browser client: 24 characters from an alphabet without
//! look-alikes (0 O o 1 l I), quotes and spaces, every class present, unbiased by rejection.

use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijkmnpqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!#%+-=?@_";
pub const LENGTH: usize = 24;

pub fn alphabet() -> String {
    [LOWER, UPPER, DIGITS, SYMBOLS].concat()
}

/// Random password from `random` (a source of uniform bytes; the system one by default).
pub fn generate_with(length: usize, mut random: impl FnMut(&mut [u8])) -> Zeroizing<String> {
    let alphabet: Vec<char> = alphabet().chars().collect();
    let n = alphabet.len();
    // The largest multiple of n that fits in a byte: bytes above it would favour the first chars.
    let limit = 256 - (256 % n);
    loop {
        let mut out = Zeroizing::new(String::with_capacity(length * 4));
        let mut buf = Zeroizing::new(vec![0u8; length * 2]);
        while out.chars().count() < length {
            random(&mut buf);
            for &b in buf.iter() {
                if (b as usize) < limit && out.chars().count() < length {
                    out.push(alphabet[b as usize % n]);
                }
            }
        }
        let all = [LOWER, UPPER, DIGITS, SYMBOLS]
            .iter()
            .all(|set| out.chars().any(|c| set.contains(c)));
        if all {
            return out;
        }
    }
}

pub fn generate() -> Zeroizing<String> {
    generate_with(LENGTH, |b| {
        getrandom::fill(b).expect("system random number generator is unavailable")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay(bytes: Vec<u8>) -> impl FnMut(&mut [u8]) {
        let mut i = 0;
        move |b: &mut [u8]| {
            for x in b.iter_mut() {
                *x = bytes[i % bytes.len()];
                i += 1;
            }
        }
    }

    #[test]
    fn same_alphabet_as_the_browser() {
        let a = alphabet();
        assert_eq!(
            a,
            "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%+-=?@_"
        );
        for bad in ['0', 'O', 'o', '1', 'l', 'I', '\'', '"', ' ', '\\'] {
            assert!(!a.contains(bad), "{bad}");
        }
    }

    #[test]
    fn length_classes_and_uniqueness() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let p = generate();
            assert_eq!(p.chars().count(), LENGTH);
            assert!(p.chars().all(|c| alphabet().contains(c)));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            seen.insert(p.to_string());
        }
        assert_eq!(seen.len(), 200);
    }

    #[test]
    fn bytes_above_the_limit_are_rejected_and_classes_enforced() {
        let a: Vec<char> = alphabet().chars().collect();
        let idx = |c: char| a.iter().position(|x| *x == c).unwrap() as u8;
        let limit = (256 - 256 % a.len()) as u8;
        let p = generate_with(
            4,
            replay(vec![limit, 255, idx('a'), idx('B'), idx('2'), idx('!')]),
        );
        assert_eq!(p.as_str(), "aB2!");
        // The first attempt lacks a symbol: it is thrown away.
        let mut calls = 0;
        let p = generate_with(4, move |b: &mut [u8]| {
            calls += 1;
            let src = if calls == 1 {
                [idx('a'), idx('b'), idx('C'), idx('3')]
            } else {
                [idx('a'), idx('B'), idx('2'), idx('!')]
            };
            for (i, x) in b.iter_mut().enumerate() {
                *x = src[i % 4];
            }
        });
        assert_eq!(p.as_str(), "aB2!");
    }
}
