//! Hand-written Levenshtein edit distance.
//!
//! Used to derive [`CommandObserved::edit_distance_prev`](aegis_sdk::EventPayload::CommandObserved)
//! — a structural signal (how much a command changed from the previous one)
//! that never leaks command content. Implemented in two-row, O(min(len))-space
//! DP so it stays cheap and has no external dependency.

/// Levenshtein (edit) distance between two strings, measured over Unicode
/// scalar values (`char`), not bytes. `0` means identical.
pub fn levenshtein(a: &str, b: &str) -> usize {
    // Operate on chars so multi-byte input does not inflate the distance.
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    // Keep the shorter string on the inner axis to minimize the row width.
    let (a, b) = if a.len() < b.len() { (b, a) } else { (a, b) };

    // `prev[j]` is the distance for the previous outer row; `curr[j]` the one
    // being filled. Row 0 is the cost of deleting the first j chars of `b`.
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];

    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1) // deletion
                .min(curr[j] + 1) // insertion
                .min(prev[j] + cost); // substitution
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "abc"), 3);
    }

    #[test]
    fn classic_kitten_sitting() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn identical_is_zero() {
        assert_eq!(levenshtein("ls -la /etc", "ls -la /etc"), 0);
    }

    #[test]
    fn is_symmetric() {
        assert_eq!(levenshtein("ls", "ls -l"), levenshtein("ls -l", "ls"));
        assert_eq!(levenshtein("ls", "ls -l"), 3);
    }

    #[test]
    fn counts_chars_not_bytes() {
        // A 2-char accented string vs empty -> distance 2, not byte length 4.
        assert_eq!(levenshtein("é!", ""), 2);
    }
}
