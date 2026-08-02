//! SHA-256, for detecting changes to protected files.
//!
//! # Why cryptographic, and why hand-written
//!
//! A protected-file check that used a fast non-cryptographic hash would be
//! defeatable: a command that modifies a file and then pads it to restore the
//! checksum passes the check, and the whole point of the check is to catch a
//! command that modified something it should not have. Collision resistance is
//! the property being relied on, so it has to be a hash that has it.
//!
//! Hand-written because the workspace carries no dependencies (DESIGN.md § 9)
//! and SHA-256 is small, fixed, and verifiable against published vectors —
//! which is exactly the kind of thing worth writing rather than pulling in.

/// Streaming SHA-256, so a large file is hashed without being read into memory.
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buflen: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);

        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }

        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bitlen = self.len.wrapping_mul(8);

        // Pad with 0x80, then zeros, then the 64-bit big-endian length.
        self.update_raw(&[0x80]);
        while self.buflen != 56 {
            self.update_raw(&[0]);
        }
        let lenbytes = bitlen.to_be_bytes();
        self.buf[56..64].copy_from_slice(&lenbytes);
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Buffer bytes without counting them towards the message length, for
    /// padding.
    fn update_raw(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buflen] = b;
            self.buflen += 1;
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// Hash a file without reading it all into memory.
pub fn hash_file(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finish())
}

pub fn hex(digest: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        hex(&hash(s.as_bytes()))
    }

    #[test]
    fn published_vectors() {
        // FIPS 180-4 and the usual suspects. If these pass, the implementation
        // is right; there is no partial credit with a hash.
        assert_eq!(h(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(h("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            h("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            h("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn a_million_a_s() {
        // The classic long-message vector: exercises multi-block and the
        // length encoding together.
        let mut s = Sha256::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(
            hex(&s.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        // Chunk boundaries are where a buffered hash goes wrong, so try every
        // split of a message that straddles several blocks.
        let msg: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let want = hash(&msg);
        for split in [1usize, 55, 56, 63, 64, 65, 127, 128, 129, 500, 999] {
            let mut s = Sha256::new();
            s.update(&msg[..split]);
            s.update(&msg[split..]);
            assert_eq!(s.finish(), want, "split at {split}");
        }
    }

    #[test]
    fn byte_at_a_time_matches() {
        let msg = b"the quick brown fox jumps over the lazy dog, repeatedly and at length";
        let mut s = Sha256::new();
        for b in msg {
            s.update(&[*b]);
        }
        assert_eq!(s.finish(), hash(msg));
    }

    #[test]
    fn a_changed_byte_changes_the_digest() {
        assert_ne!(hash(b"protected content"), hash(b"protected contenu"));
    }

    #[test]
    fn hashes_a_file_from_disk() {
        let p = std::env::temp_dir().join("shellguard-sha-test.bin");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(hex(&hash_file(&p).unwrap()), h("abc"));
        // Larger than the read buffer, to exercise the loop.
        let big = vec![b'a'; 200_000];
        std::fs::write(&p, &big).unwrap();
        assert_eq!(hash_file(&p).unwrap(), hash(&big));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn hex_is_lowercase_and_fixed_width() {
        let d = hash(b"");
        let s = hex(&d);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
