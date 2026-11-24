#![allow(clippy::unwrap_used)]
//! Vetores oficiais: Argon2id (RFC 9106 §5.3) e AES-256-GCM (McGrew–Viega / NIST, casos 13–16 e
//! CAVP com AAD), incluindo AAD, tag errada e payload vazio. Bibliotecas RustCrypto, sem
//! implementação própria.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use hex_literal_free::h;
use keyvault_core::crypto::testing::{aes256gcm_decrypt, aes256gcm_encrypt};

mod hex_literal_free {
    pub fn h(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
}

#[test]
fn argon2id_rfc9106_vector() {
    // RFC 9106 §5.3: Argon2id v0x13, m=32 KiB, t=3, p=4, password 32×0x01, salt 16×0x02,
    // secret 8×0x03, associated data 12×0x04, tag 32 bytes.
    let params =
        ParamsBuilder::new().m_cost(32).t_cost(3).p_cost(4).output_len(32).data(AssociatedData::new(&[0x04; 12]).unwrap()).build().unwrap();
    let ctx = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out).unwrap();
    assert_eq!(out.to_vec(), h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));
}

struct V {
    key: &'static str,
    iv: &'static str,
    pt: &'static str,
    aad: &'static str,
    ct: &'static str,
    tag: &'static str,
}

const VECTORS: &[V] = &[
    // Caso 13: chave zero, payload vazio.
    V {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "",
        aad: "",
        ct: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    // Caso 14.
    V {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        pt: "00000000000000000000000000000000",
        aad: "",
        ct: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    // Caso 15.
    V {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        aad: "",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
    // Caso 16: com AAD.
    V {
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        iv: "cafebabefacedbaddecaf888",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    },
    // NIST CAVP gcmEncryptExtIV256 (Count 0, PTlen=0, AADlen=0).
    V {
        key: "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        iv: "516c33929df5a3284ff463d7",
        pt: "",
        aad: "",
        ct: "",
        tag: "bdc1ac884d332457a1d2664f168c76f0",
    },
];

fn arr<const N: usize>(v: Vec<u8>) -> [u8; N] {
    v.try_into().unwrap()
}

#[test]
fn aes256gcm_official_vectors() {
    for (i, v) in VECTORS.iter().enumerate() {
        let key: [u8; 32] = arr(h(v.key));
        let iv: [u8; 12] = arr(h(v.iv));
        let (pt, aad) = (h(v.pt), h(v.aad));
        let mut expected = h(v.ct);
        expected.extend_from_slice(&h(v.tag));
        let got = aes256gcm_encrypt(&key, &iv, &pt, &aad);
        assert_eq!(got, expected, "vetor {i}");
        assert_eq!(aes256gcm_decrypt(&key, &iv, &got, &aad).unwrap(), pt, "vetor {i}");
        // Tag errada.
        let mut bad = got.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(aes256gcm_decrypt(&key, &iv, &bad, &aad).is_none(), "tag adulterada aceita no vetor {i}");
        // AAD errada.
        let mut aad2 = aad.clone();
        aad2.push(0);
        assert!(aes256gcm_decrypt(&key, &iv, &got, &aad2).is_none(), "AAD errada aceita no vetor {i}");
        // Tag truncada nunca é aceita.
        assert!(aes256gcm_decrypt(&key, &iv, &got[..got.len() - 1], &aad).is_none());
    }
}
