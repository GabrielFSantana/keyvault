//! Fonte de aleatoriedade. Produção usa exclusivamente o CSPRNG do sistema operacional
//! (`getrandom`, que no Windows usa `ProcessPrng`). Não há fallback nem RNG próprio.
//! A abstração existe para que testes possam injetar falhas e sequências determinísticas.

use crate::error::{CoreError, Result};

pub trait SecureRandom: Send + Sync {
    /// Preenche `dest` inteiramente ou falha. Em falha o conteúdo de `dest` deve ser descartado.
    fn fill(&self, dest: &mut [u8]) -> Result<()>;
}

/// CSPRNG do sistema operacional.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|_| CoreError::Rng)
    }
}

/// Preenche um array novo; em falha zera o buffer parcial antes de retornar o erro.
pub fn random_array<const N: usize>(rng: &dyn SecureRandom) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    if let Err(e) = rng.fill(&mut out) {
        zeroize::Zeroize::zeroize(&mut out);
        return Err(e);
    }
    Ok(out)
}

/// Inteiro uniforme em `0..bound` por amostragem por rejeição (sem viés de módulo).
pub fn uniform_u32(rng: &dyn SecureRandom, bound: u32) -> Result<u32> {
    assert!(bound > 0, "bound deve ser positivo");
    // threshold = 2^32 mod bound. O intervalo [threshold, 2^32) tem tamanho múltiplo de `bound`,
    // então aceitar apenas valores nele torna `v % bound` exatamente uniforme.
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let v = u32::from_le_bytes(random_array::<4>(rng)?);
        if v >= threshold {
            return Ok(v % bound);
        }
    }
}

#[cfg(any(test, feature = "test-instrumentation"))]
#[allow(clippy::unwrap_used)]
pub mod testing {
    //! RNGs apenas para testes (dados fictícios).
    use super::*;
    use std::sync::Mutex;

    /// Sempre falha.
    pub struct FailingRandom;
    impl SecureRandom for FailingRandom {
        fn fill(&self, _dest: &mut [u8]) -> Result<()> {
            Err(CoreError::Rng)
        }
    }

    /// Falha depois de `n` chamadas bem-sucedidas ao CSPRNG real.
    pub struct FailAfter {
        remaining: Mutex<usize>,
    }
    impl FailAfter {
        pub fn new(n: usize) -> Self {
            Self { remaining: Mutex::new(n) }
        }
    }
    impl SecureRandom for FailAfter {
        fn fill(&self, dest: &mut [u8]) -> Result<()> {
            let mut r = self.remaining.lock().unwrap();
            if *r == 0 {
                return Err(CoreError::Rng);
            }
            *r -= 1;
            OsRandom.fill(dest)
        }
    }

    /// Devolve bytes de uma fila fixa (vetores determinísticos). Falha quando esgota.
    pub struct ScriptedRandom {
        queue: Mutex<std::collections::VecDeque<u8>>,
    }
    impl ScriptedRandom {
        pub fn new(bytes: &[u8]) -> Self {
            Self { queue: Mutex::new(bytes.iter().copied().collect()) }
        }
    }
    impl SecureRandom for ScriptedRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<()> {
            let mut q = self.queue.lock().unwrap();
            if q.len() < dest.len() {
                return Err(CoreError::Rng);
            }
            for b in dest.iter_mut() {
                *b = q.pop_front().unwrap();
            }
            Ok(())
        }
    }
}
