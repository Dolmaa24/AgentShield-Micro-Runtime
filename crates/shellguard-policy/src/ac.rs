//! Aho-Corasick prefilter.
//!
//! # Why this is here
//!
//! Most rules name a program, so they can be found by hashing on the program
//! basename and never looked at again. The rules that *cannot* be indexed that
//! way are the ones matching on argument text regardless of program — "any
//! command mentioning `/etc/shadow`", "any argument containing `..`". Those are
//! the interesting rules and there are a lot of them, and the obvious
//! implementation runs every one of their needles over the command text.
//!
//! At 200 needles and a 200-byte command that is 40 000 byte comparisons per
//! evaluation, which is where a naive gate's latency budget goes. Aho-Corasick
//! answers "which of these 200 needles appear" in a single pass over the text,
//! independent of how many needles there are. Adding the 201st rule then costs
//! nothing at evaluation time, which is the property that lets a ruleset grow
//! without anyone having to think about the latency budget again.
//!
//! Transitions are stored sorted-sparse rather than as dense 256-entry rows.
//! Fanout past the first byte or two is almost always under four, so a linear
//! scan of a short slice beats an indexed lookup into a table that does not fit
//! in cache, and the automaton stays small enough to sit beside the rules.

/// A fixed-size bitset, used to collect which patterns matched without
/// allocating per evaluation.
#[derive(Clone, Debug, Default)]
pub struct BitSet {
    words: Vec<u64>,
    len: usize,
}

impl BitSet {
    pub fn with_capacity(bits: usize) -> Self {
        BitSet { words: vec![0; bits.div_ceil(64)], len: bits }
    }

    pub fn resize(&mut self, bits: usize) {
        self.words.resize(bits.div_ceil(64), 0);
        self.len = bits;
    }

    pub fn clear(&mut self) {
        self.words.iter_mut().for_each(|w| *w = 0);
    }

    #[inline]
    pub fn insert(&mut self, i: usize) {
        if i < self.len {
            self.words[i / 64] |= 1u64 << (i % 64);
        }
    }

    #[inline]
    pub fn contains(&self, i: usize) -> bool {
        i < self.len && (self.words[i / 64] >> (i % 64)) & 1 == 1
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, w)| {
            let mut bits = *w;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(wi * 64 + b)
            })
        })
    }
}

#[derive(Debug)]
struct Node {
    /// Sorted by byte, so lookup is a short linear scan over contiguous memory.
    next: Vec<(u8, u32)>,
    fail: u32,
    /// Pattern ids matching at this node, with fail-link outputs already merged
    /// in so matching never has to walk the suffix chain.
    out: Vec<u32>,
}

impl Node {
    fn new() -> Self {
        Node { next: Vec::new(), fail: 0, out: Vec::new() }
    }

    #[inline]
    fn goto(&self, b: u8) -> Option<u32> {
        // Patterns are ASCII-ish and fanout is tiny; a linear scan avoids the
        // branch misprediction a binary search would cost at this size.
        self.next.iter().find(|(k, _)| *k == b).map(|(_, v)| *v)
    }
}

#[derive(Debug)]
pub struct AhoCorasick {
    nodes: Vec<Node>,
    patterns: usize,
    /// True when the automaton holds nothing, so scanning can be skipped
    /// outright rather than walking the text to find nothing.
    empty: bool,
}

impl AhoCorasick {
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        let mut nodes = vec![Node::new()];

        for (id, pat) in patterns.iter().enumerate() {
            let bytes = pat.as_ref().as_bytes();
            if bytes.is_empty() {
                continue;
            }
            let mut cur = 0u32;
            for &b in bytes {
                match nodes[cur as usize].goto(b) {
                    Some(next) => cur = next,
                    None => {
                        let next = nodes.len() as u32;
                        nodes.push(Node::new());
                        let slot = &mut nodes[cur as usize].next;
                        let at = slot.partition_point(|(k, _)| *k < b);
                        slot.insert(at, (b, next));
                        cur = next;
                    }
                }
            }
            nodes[cur as usize].out.push(id as u32);
        }

        // Breadth-first fail links. A node's fail target is the longest proper
        // suffix of its path that is also a prefix of some pattern.
        let mut queue = std::collections::VecDeque::new();
        let root_children: Vec<(u8, u32)> = nodes[0].next.clone();
        for (_, child) in root_children {
            nodes[child as usize].fail = 0;
            queue.push_back(child);
        }

        while let Some(cur) = queue.pop_front() {
            let children: Vec<(u8, u32)> = nodes[cur as usize].next.clone();
            for (b, child) in children {
                // Walk the fail chain until a node has a transition on `b`.
                let mut f = nodes[cur as usize].fail;
                loop {
                    if let Some(t) = nodes[f as usize].goto(b) {
                        if t != child {
                            nodes[child as usize].fail = t;
                            break;
                        }
                    }
                    if f == 0 {
                        nodes[child as usize].fail = 0;
                        break;
                    }
                    f = nodes[f as usize].fail;
                }
                // Merge the fail target's outputs so match time never chases
                // suffix links.
                let inherited = nodes[nodes[child as usize].fail as usize].out.clone();
                nodes[child as usize].out.extend(inherited);
                queue.push_back(child);
            }
        }

        let empty = nodes.len() == 1;
        AhoCorasick { nodes, patterns: patterns.len(), empty }
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }

    /// Record every pattern occurring in `hay` into `out`.
    ///
    /// One pass, no allocation, and the cost does not depend on how many
    /// patterns the automaton holds.
    pub fn scan_into(&self, hay: &[u8], out: &mut BitSet) {
        if self.empty {
            return;
        }
        let mut state = 0u32;
        for &b in hay {
            loop {
                if let Some(next) = self.nodes[state as usize].goto(b) {
                    state = next;
                    break;
                }
                if state == 0 {
                    break;
                }
                state = self.nodes[state as usize].fail;
            }
            for &id in &self.nodes[state as usize].out {
                out.insert(id as usize);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(pats: &[&str], hay: &str) -> Vec<usize> {
        let ac = AhoCorasick::new(pats);
        let mut set = BitSet::with_capacity(pats.len());
        ac.scan_into(hay.as_bytes(), &mut set);
        let mut v: Vec<usize> = set.iter().collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn finds_all_occurrences() {
        assert_eq!(hits(&["he", "she", "his", "hers"], "ushers"), vec![0, 1, 3]);
    }

    #[test]
    fn finds_overlapping_and_nested_patterns() {
        // `a` is a suffix of `ba`, so the fail-link output merge has to fire.
        assert_eq!(hits(&["a", "ba", "bab"], "bab"), vec![0, 1, 2]);
    }

    #[test]
    fn no_match_is_empty() {
        assert!(hits(&["rm -rf", "/etc/shadow"], "git status").is_empty());
    }

    #[test]
    fn realistic_needles() {
        let pats = &["/etc/shadow", "/etc/passwd", "..", "~/.ssh", "/dev/"];
        assert_eq!(hits(pats, "cat /etc/shadow"), vec![0]);
        assert_eq!(hits(pats, "cp ~/.ssh/id_rsa /dev/null"), vec![3, 4]);
        assert_eq!(hits(pats, "cd ../.."), vec![2]);
    }

    #[test]
    fn empty_automaton_scans_nothing() {
        let ac = AhoCorasick::new::<&str>(&[]);
        assert!(ac.is_empty());
        let mut set = BitSet::with_capacity(0);
        ac.scan_into(b"anything", &mut set);
        assert!(set.is_empty());
    }

    #[test]
    fn empty_patterns_are_skipped_not_matched_everywhere() {
        let pats = &["", "rm"];
        assert_eq!(hits(pats, "rm x"), vec![1]);
    }

    #[test]
    fn bitset_roundtrip() {
        let mut b = BitSet::with_capacity(200);
        for i in [0usize, 63, 64, 65, 199] {
            b.insert(i);
        }
        assert_eq!(b.iter().collect::<Vec<_>>(), vec![0, 63, 64, 65, 199]);
        assert!(b.contains(64));
        assert!(!b.contains(66));
        // Out-of-range inserts are dropped rather than panicking; this runs on
        // untrusted input and must not have a crash path.
        b.insert(10_000);
        assert!(!b.contains(10_000));
        b.clear();
        assert!(b.is_empty());
    }
}
