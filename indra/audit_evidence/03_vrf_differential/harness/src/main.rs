use indra_crypto::{vrf_prove, vrf_verify, VrfKeypair, VrfOutput, VrfProof};
use std::{
    env, fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const CASES: usize = 1_000;
const CORPUS_SEED: u64 = 0x494e_4452_412d_5652;
const Q: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

struct Reference {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Reference {
    fn start(path: &str) -> Self {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start pinned reference adapter");
        let input = BufWriter::new(child.stdin.take().unwrap());
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }

    fn request(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").unwrap();
        self.input.flush().unwrap();
        let mut response = String::new();
        self.output.read_line(&mut response).unwrap();
        assert!(!response.is_empty(), "reference adapter terminated");
        response.trim().to_owned()
    }

    fn prove(&mut self, seed: &[u8; 32], alpha: &[u8]) -> ([u8; 32], Vec<u8>, [u8; 64]) {
        let response = self.request(&format!("prove {} {}", hex(seed), token(alpha)));
        let fields: Vec<_> = response.split_ascii_whitespace().collect();
        assert_eq!(
            fields.first(),
            Some(&"OK"),
            "reference prove failed: {response}"
        );
        assert_eq!(fields.len(), 4, "malformed reference response: {response}");
        (array(fields[1]), decode(fields[2]), array(fields[3]))
    }

    fn verify(&mut self, pk: &[u8; 32], alpha: &[u8], proof: &[u8], beta: &[u8; 64]) -> bool {
        self.request(&format!(
            "verify {} {} {} {}",
            hex(pk),
            token(alpha),
            hex(proof),
            hex(beta)
        )) == "ACCEPT"
    }

    fn proof_to_hash(&mut self, proof: &[u8]) -> Option<[u8; 64]> {
        let response = self.request(&format!("proof_to_hash {}", hex(proof)));
        let fields: Vec<_> = response.split_ascii_whitespace().collect();
        (fields.first() == Some(&"OK")).then(|| array(fields[1]))
    }
}

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |v: u8| match v {
                b'0'..=b'9' => v - b'0',
                b'a'..=b'f' => v - b'a' + 10,
                _ => panic!("invalid hex from reference"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode(value).try_into().unwrap()
}

fn token(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".into()
    } else {
        hex(bytes)
    }
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn bytes(state: &mut u64, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    for chunk in out.chunks_mut(8) {
        let word = splitmix(state).to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    out
}

fn fixture(index: usize) -> ([u8; 32], Vec<u8>) {
    let mut state = CORPUS_SEED ^ (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let seed = bytes(&mut state, 32).try_into().unwrap();
    let lengths = [0, 1, 7, 31, 32, 63, 128, 255, 1024];
    let alpha = bytes(&mut state, lengths[index % lengths.len()]);
    (seed, alpha)
}

fn indra_accepts(pk: &[u8; 32], alpha: &[u8], proof: &[u8], beta: &[u8; 64]) -> bool {
    vrf_verify(pk, alpha, &VrfOutput(*beta), &VrfProof(proof.to_vec())).is_ok()
}

fn mismatch(
    kind: &str,
    index: usize,
    seed: &[u8; 32],
    alpha: &[u8],
    pk: &[u8; 32],
    proof: &[u8],
    beta: &[u8; 64],
    indra: &str,
    reference: &str,
) -> ! {
    let artifact = format!(
        "kind={kind}\nindex={index}\nseed={}\nalpha={}\npublic_key={}\nproof={}\noutput={}\nindra={indra}\nreference={reference}\n",
        hex(seed), hex(alpha), hex(pk), hex(proof), hex(beta)
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../mismatch.txt");
    fs::write(&path, artifact).unwrap();
    panic!(
        "differential mismatch; artifact written to {}",
        path.display()
    );
}

fn check_vectors(reference: &mut Reference) {
    let vectors = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501", "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801", "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04", "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"),
    ];
    for (seed, alpha, expected_pk, expected_proof, expected_beta) in vectors {
        let (pk, proof, beta) = reference.prove(&array(seed), &decode(alpha));
        assert_eq!(hex(&pk), expected_pk, "reference RFC public key mismatch");
        assert_eq!(hex(&proof), expected_proof, "reference RFC proof mismatch");
        assert_eq!(hex(&beta), expected_beta, "reference RFC output mismatch");
    }
}

fn main() {
    let reference_path = env::args().nth(1).expect("usage: harness REFERENCE_CLI");
    let mut reference = Reference::start(&reference_path);
    check_vectors(&mut reference);
    println!("official_rfc_vectors=3 matched=true");

    let mut malformed_count = 0usize;
    for index in 0..CASES {
        let (seed, alpha) = fixture(index);
        let keypair = VrfKeypair::from_seed(&seed);
        let (indra_beta, indra_proof) = vrf_prove(&keypair, &alpha);
        let (ref_pk, ref_proof, ref_beta) = reference.prove(&seed, &alpha);
        if ref_pk != keypair.public_key || ref_proof != indra_proof.0 || ref_beta != indra_beta.0 {
            mismatch(
                "positive-bytes",
                index,
                &seed,
                &alpha,
                &keypair.public_key,
                &indra_proof.0,
                &indra_beta.0,
                "generated",
                "generated-different",
            );
        }
        if !reference.verify(&keypair.public_key, &alpha, &indra_proof.0, &indra_beta.0) {
            mismatch(
                "indra-prove-reference-verify",
                index,
                &seed,
                &alpha,
                &keypair.public_key,
                &indra_proof.0,
                &indra_beta.0,
                "accept",
                "reject",
            );
        }
        if !indra_accepts(&ref_pk, &alpha, &ref_proof, &ref_beta) {
            mismatch(
                "reference-prove-indra-verify",
                index,
                &seed,
                &alpha,
                &ref_pk,
                &ref_proof,
                &ref_beta,
                "reject",
                "accept",
            );
        }
        if reference.proof_to_hash(&indra_proof.0) != Some(indra_beta.0) {
            mismatch(
                "proof-to-hash",
                index,
                &seed,
                &alpha,
                &keypair.public_key,
                &indra_proof.0,
                &indra_beta.0,
                "output",
                "different-output",
            );
        }

        let (other_seed, _) = fixture(index + CASES);
        let other_pk = VrfKeypair::from_seed(&other_seed).public_key;
        let mut wrong_alpha = alpha.clone();
        wrong_alpha.push(0x80);
        let mut gamma = indra_proof.0.clone();
        gamma[0] ^= 1;
        let mut challenge = indra_proof.0.clone();
        challenge[32] ^= 1;
        let mut scalar = indra_proof.0.clone();
        scalar[48] ^= 1;
        let mut output = indra_beta.0;
        output[0] ^= 1;
        let mut overlong = indra_proof.0.clone();
        overlong.push(0);
        let mut noncanonical = indra_proof.0.clone();
        noncanonical[48..80].copy_from_slice(&Q);
        let malformed = [
            (
                "wrong-alpha",
                wrong_alpha.as_slice(),
                keypair.public_key,
                indra_proof.0.as_slice(),
                indra_beta.0,
            ),
            (
                "wrong-public-key",
                alpha.as_slice(),
                other_pk,
                indra_proof.0.as_slice(),
                indra_beta.0,
            ),
            (
                "modified-gamma",
                alpha.as_slice(),
                keypair.public_key,
                gamma.as_slice(),
                indra_beta.0,
            ),
            (
                "modified-challenge",
                alpha.as_slice(),
                keypair.public_key,
                challenge.as_slice(),
                indra_beta.0,
            ),
            (
                "modified-scalar",
                alpha.as_slice(),
                keypair.public_key,
                scalar.as_slice(),
                indra_beta.0,
            ),
            (
                "modified-output",
                alpha.as_slice(),
                keypair.public_key,
                indra_proof.0.as_slice(),
                output,
            ),
            (
                "truncated-proof",
                alpha.as_slice(),
                keypair.public_key,
                &indra_proof.0[..79],
                indra_beta.0,
            ),
            (
                "overlong-proof",
                alpha.as_slice(),
                keypair.public_key,
                overlong.as_slice(),
                indra_beta.0,
            ),
            (
                "noncanonical-scalar",
                alpha.as_slice(),
                keypair.public_key,
                noncanonical.as_slice(),
                indra_beta.0,
            ),
        ];
        for (kind, candidate_alpha, candidate_pk, candidate_proof, candidate_beta) in malformed {
            let indra = indra_accepts(
                &candidate_pk,
                candidate_alpha,
                candidate_proof,
                &candidate_beta,
            );
            let reference_result = reference.verify(
                &candidate_pk,
                candidate_alpha,
                candidate_proof,
                &candidate_beta,
            );
            malformed_count += 1;
            if indra != reference_result {
                mismatch(
                    kind,
                    index,
                    &seed,
                    candidate_alpha,
                    &candidate_pk,
                    candidate_proof,
                    &candidate_beta,
                    if indra { "accept" } else { "reject" },
                    if reference_result { "accept" } else { "reject" },
                );
            }
        }
    }
    println!("positive_cases={CASES}");
    println!("malformed_cases={malformed_count}");
    println!("prove_verify_output_mismatches=0");
    println!("accept_reject_disagreements=0");
}
