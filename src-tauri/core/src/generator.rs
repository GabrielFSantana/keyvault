//! Gerador de senhas com CSPRNG do SO, amostragem sem viés e garantia das classes selecionadas.

use zeroize::Zeroizing;

use crate::error::{CoreError, Field, Result};
use crate::limits::{GEN_DEFAULT_LEN, GEN_MAX_LEN, GEN_MIN_LEN};
use crate::rng::{SecureRandom, uniform_u32};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Caracteres facilmente confundidos.
pub const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions {
            length: GEN_DEFAULT_LEN,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

fn class(set: &str, exclude_ambiguous: bool) -> Vec<char> {
    set.chars().filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(*c)).collect()
}

pub fn generate(opts: &GeneratorOptions, rng: &dyn SecureRandom) -> Result<Zeroizing<String>> {
    if !(GEN_MIN_LEN..=GEN_MAX_LEN).contains(&opts.length) {
        return Err(CoreError::Validation(Field::GeneratorOptions));
    }
    let mut classes: Vec<Vec<char>> = Vec::new();
    for (on, set) in [(opts.lowercase, LOWER), (opts.uppercase, UPPER), (opts.digits, DIGITS), (opts.symbols, SYMBOLS)] {
        if on {
            let c = class(set, opts.exclude_ambiguous);
            if c.is_empty() {
                return Err(CoreError::Validation(Field::GeneratorOptions));
            }
            classes.push(c);
        }
    }
    // Opções impossíveis: nenhuma classe ou mais classes do que posições.
    if classes.is_empty() || classes.len() > opts.length {
        return Err(CoreError::Validation(Field::GeneratorOptions));
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(opts.length));
    // Um caractere garantido de cada classe selecionada...
    for c in &classes {
        chars.push(c[uniform_u32(rng, c.len() as u32)? as usize]);
    }
    // ...o restante uniforme sobre a união...
    while chars.len() < opts.length {
        chars.push(all[uniform_u32(rng, all.len() as u32)? as usize]);
    }
    // ...e embaralhamento Fisher–Yates sem viés para não fixar posições.
    for i in (1..chars.len()).rev() {
        let j = uniform_u32(rng, (i + 1) as u32)? as usize;
        chars.swap(i, j);
    }
    let mut out = Zeroizing::new(String::with_capacity(opts.length * 4));
    out.extend(chars.iter());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::OsRandom;
    use crate::rng::testing::FailingRandom;

    #[test]
    fn default_has_24_chars_and_all_classes() {
        for _ in 0..200 {
            let p = generate(&GeneratorOptions::default(), &OsRandom).unwrap();
            assert_eq!(p.chars().count(), 24);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn bounds_and_impossible_options() {
        let mut o = GeneratorOptions { length: 15, ..Default::default() };
        assert!(generate(&o, &OsRandom).is_err());
        o.length = 129;
        assert!(generate(&o, &OsRandom).is_err());
        o.length = 128;
        assert_eq!(generate(&o, &OsRandom).unwrap().chars().count(), 128);
        let none = GeneratorOptions { lowercase: false, uppercase: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate(&none, &OsRandom).is_err());
    }

    #[test]
    fn exclude_ambiguous() {
        let o = GeneratorOptions { exclude_ambiguous: true, length: 128, ..Default::default() };
        for _ in 0..100 {
            let p = generate(&o, &OsRandom).unwrap();
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rng_failure_aborts() {
        assert!(matches!(generate(&GeneratorOptions::default(), &FailingRandom), Err(CoreError::Rng)));
    }

    #[test]
    fn digits_only_distribution_is_roughly_uniform() {
        // Teste estatístico simples (qui-quadrado) sobre 10 dígitos.
        let o =
            GeneratorOptions { lowercase: false, uppercase: false, digits: true, symbols: false, exclude_ambiguous: false, length: 128 };
        let mut counts = [0u64; 10];
        for _ in 0..400 {
            for c in generate(&o, &OsRandom).unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        let n: u64 = counts.iter().sum();
        let exp = n as f64 / 10.0;
        let chi2: f64 = counts.iter().map(|&c| (c as f64 - exp).powi(2) / exp).sum();
        // gl=9; p=0.001 → 27.88
        assert!(chi2 < 27.88, "chi2={chi2}");
    }
}
