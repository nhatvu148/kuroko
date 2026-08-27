//! Locale-aware matching for UI labels.
//!
//! Every name-based match in this crate compares a string a caller typed
//! against a string Windows produced, and those two strings reach this point
//! by very different roads. The caller's may have been typed on macOS, pasted
//! from documentation, or produced by a model. Windows' comes from whatever
//! the application's resource file says in whatever language is installed.
//! Four things go wrong, and all four are ordinary rather than exotic:
//!
//! - **Case outside ASCII.** `eq_ignore_ascii_case` folds `A-Z` and nothing
//!   else, so German `Öffnen` never matched `öffnen`.
//! - **Composition.** macOS emits NFD, Windows reports NFC. Vietnamese `Tệp`
//!   is one codepoint in the first and three in the second; they are the same
//!   word and never compared equal.
//! - **Width.** Japanese input yields full-width `Ａ１`, which is not `A1`.
//! - **Mnemonics.** Localised Windows menus render the access key in the
//!   label: `ファイル(F)`, `文件(F)`, `&Datei`. The visible word is a prefix
//!   of the reported name, not the whole of it.
//!
//! ## Why a ladder rather than one lenient comparison
//!
//! The obvious fix is to normalise everything aggressively and compare once.
//! That trades one failure for a worse one: leniency merges labels that were
//! distinct, so a selector that used to identify one element starts matching
//! several, and the caller gets `ambiguous` where it used to get a click.
//! Loosening a matcher should never break a case that already worked.
//!
//! So matching is tiered, tightest first, and a search keeps only its best
//! tier ([`keep_best`]). If any element matches exactly, the lenient tiers are
//! discarded entirely and cannot contribute ambiguity. Leniency is reachable
//! only where strictness found nothing, which makes each tier strictly a
//! recovery of cases that previously failed outright.
//!
//! The tier that succeeded is reported back to the caller, because
//! `matched_by: "affix"` means "I stripped part of the label to make this fit"
//! and that is worth seeing.

use schemars::JsonSchema;
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

/// How much leniency a match required. Ordering is meaningful and is the whole
/// point: `Exact < Case < Normalized < Affix`, so `min()` picks the tightest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MatchTier {
    /// Identical once surrounding whitespace is trimmed.
    Exact,
    /// Equal under Unicode lowercasing.
    Case,
    /// Equal under NFKC, whitespace collapsing and lowercasing. This is the
    /// tier that recovers NFD-vs-NFC and full-width-vs-half-width.
    Normalized,
    /// Equal only after removing access-key markers, a trailing mnemonic such
    /// as `(F)`, and a trailing ellipsis.
    Affix,
    /// Equal only after folding characters the OCR recogniser genuinely
    /// confuses (`I`/`l`/`1`, `O`/`0`). Produced by `crate::ocr` alone - it is
    /// a property of reading pixels, not of language - and lives here so that
    /// [`keep_best`] can rank it below every real match.
    Confusable,
}

impl MatchTier {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchTier::Exact => "exact",
            MatchTier::Case => "case",
            MatchTier::Normalized => "normalized",
            MatchTier::Affix => "affix",
            MatchTier::Confusable => "confusable",
        }
    }
}

/// Unicode lowercase, trimmed.
///
/// `str::to_lowercase` is full Unicode lowercasing, not case folding; the two
/// differ for a handful of scripts. The known gap is Turkish, where dotted and
/// dotless I do not round-trip the way a Turkish reader expects. Closing that
/// needs locale-aware folding, which needs to know the UI language, which we
/// do not currently read. Recorded rather than hidden.
pub fn fold_case(s: &str) -> String {
    s.trim().to_lowercase()
}

/// NFKC, then collapse every run of whitespace to one space, then lowercase.
///
/// NFKC rather than NFC because compatibility composition is what folds
/// full-width Latin onto ASCII. Zero-width characters are dropped outright:
/// they are invisible, carry no meaning in a label, and `char::is_whitespace`
/// does not cover them.
pub fn normalize(s: &str) -> String {
    let composed: String = s.nfkc().collect();
    let mut out = String::with_capacity(composed.len());
    let mut pending_space = false;
    for c in composed.chars() {
        if matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}') {
            continue;
        }
        if c.is_whitespace() {
            // Leading whitespace never produces a space, so this also trims.
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    out.to_lowercase()
}

/// Removes Win32 access-key markers: `&File` is `File`, `E&xit` is `Exit`,
/// and a doubled `&&` is a literal ampersand.
fn strip_access_keys(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '&' {
            if chars.peek() == Some(&'&') {
                chars.next();
                out.push('&');
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Removes a trailing localised mnemonic such as the `(f)` in `ファイル(f)`.
///
/// Restricted to a single ASCII *letter* on purpose. `Step (1)` and
/// `Model (2)` are real labels whose parenthesised digit is content, and
/// widening this to digits would silently merge them.
fn strip_mnemonic_suffix(s: &str) -> &str {
    let t = s.trim_end();
    let Some(body) = t.strip_suffix(')') else {
        return s;
    };
    let Some((head, key)) = body.rsplit_once('(') else {
        return s;
    };
    let mut k = key.chars();
    match (k.next(), k.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() && !head.is_empty() => head.trim_end(),
        _ => s,
    }
}

fn strip_trailing_ellipsis(s: &str) -> &str {
    let t = s.trim_end();
    t.strip_suffix('…')
        .or_else(|| t.strip_suffix("..."))
        .map(str::trim_end)
        .unwrap_or(s)
}

/// [`normalize`], then peel decoration off the end until nothing more comes
/// off. Iterated because `Save As...(a)` carries two layers and one pass would
/// leave the outer one behind.
pub fn strip_affixes(s: &str) -> String {
    let mut cur = normalize(&strip_access_keys(s));
    loop {
        let next = strip_trailing_ellipsis(strip_mnemonic_suffix(&cur)).to_string();
        if next == cur {
            return cur;
        }
        cur = next;
    }
}

/// The tightest tier at which `candidate` equals `wanted`, or `None`.
pub fn tier_of(candidate: &str, wanted: &str) -> Option<MatchTier> {
    if candidate.trim() == wanted.trim() {
        return Some(MatchTier::Exact);
    }
    if fold_case(candidate) == fold_case(wanted) {
        return Some(MatchTier::Case);
    }
    if normalize(candidate) == normalize(wanted) {
        return Some(MatchTier::Normalized);
    }
    let (a, b) = (strip_affixes(candidate), strip_affixes(wanted));
    // A non-empty guard, so two labels that reduce to nothing are not "equal".
    if !a.is_empty() && a == b {
        return Some(MatchTier::Affix);
    }
    None
}

/// The substring counterpart, for OCR, where the caller supplies a fragment of
/// a line rather than a whole label.
///
/// There is no affix tier here: stripping a trailing mnemonic cannot help a
/// search that is already allowed to match part of the string.
pub fn contains_tier(haystack: &str, needle: &str) -> Option<MatchTier> {
    if needle.trim().is_empty() {
        return None;
    }
    if haystack.contains(needle.trim()) {
        return Some(MatchTier::Exact);
    }
    if fold_case(haystack).contains(&fold_case(needle)) {
        return Some(MatchTier::Case);
    }
    if normalize(haystack).contains(&normalize(needle)) {
        return Some(MatchTier::Normalized);
    }
    None
}

/// Discards every hit looser than the best tier present.
///
/// This is what stops added leniency from breaking working selectors: an exact
/// match anywhere in the result set removes the lenient ones before the caller
/// ever counts them for ambiguity.
pub fn keep_best<T>(hits: &mut Vec<T>, tier: impl Fn(&T) -> MatchTier) {
    if let Some(best) = hits.iter().map(&tier).min() {
        hits.retain(|h| tier(h) == best);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the four documented failures, each as the case that motivated it ---

    #[test]
    fn german_umlaut_folds_where_ascii_case_folding_could_not() {
        // The bug this replaced: eq_ignore_ascii_case leaves Ö and ö distinct.
        assert!(!"Öffnen".eq_ignore_ascii_case("öffnen"));
        assert_eq!(tier_of("Öffnen", "öffnen"), Some(MatchTier::Case));
    }

    #[test]
    fn vietnamese_matches_across_nfd_and_nfc() {
        // Typed on macOS (NFD) against a name reported by Windows (NFC).
        let nfc = "T\u{1ec7}p";
        let nfd = "Te\u{323}\u{302}p";
        assert_ne!(nfc, nfd, "the test is meaningless if these are equal");
        assert_eq!(tier_of(nfc, nfd), Some(MatchTier::Normalized));
    }

    #[test]
    fn japanese_menu_matches_without_its_mnemonic() {
        assert_eq!(tier_of("ファイル(F)", "ファイル"), Some(MatchTier::Affix));
        assert_eq!(tier_of("文件(E)", "文件"), Some(MatchTier::Affix));
    }

    #[test]
    fn full_width_latin_matches_half_width() {
        assert_eq!(tier_of("Ａ１", "a1"), Some(MatchTier::Normalized));
    }

    // --- the safety property the ladder exists to provide ---

    #[test]
    fn an_exact_match_suppresses_every_lenient_one() {
        // "Save" exists alongside "SAVE" and "&Save...". Without keep_best all
        // three match and the caller sees `ambiguous`; with it, only the exact
        // one survives and the click goes through.
        let mut hits = vec![
            ("SAVE", tier_of("SAVE", "Save").unwrap()),
            ("Save", tier_of("Save", "Save").unwrap()),
            ("&Save...", tier_of("&Save...", "Save").unwrap()),
        ];
        keep_best(&mut hits, |h| h.1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "Save");
        assert_eq!(hits[0].1, MatchTier::Exact);
    }

    #[test]
    fn ambiguity_within_one_tier_is_preserved() {
        // keep_best narrows across tiers, never within one. Two genuinely
        // identical labels must still be reported as two.
        let mut hits = vec![
            ("Materials", MatchTier::Exact),
            ("Materials", MatchTier::Exact),
        ];
        keep_best(&mut hits, |h| h.1);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn keep_best_tolerates_an_empty_search() {
        let mut empty = Vec::<(&str, MatchTier)>::new();
        keep_best(&mut empty, |h| h.1);
        assert!(empty.is_empty());
    }

    // --- leniency has to stop somewhere ---

    #[test]
    fn a_parenthesised_digit_is_content_not_a_mnemonic() {
        // Abaqus really does show "Step (1)" and "Step (2)"; folding those
        // together would make the selector ambiguous on every real model.
        assert_eq!(tier_of("Step (1)", "Step"), None);
        assert_eq!(tier_of("Step (1)", "Step (2)"), None);
    }

    #[test]
    fn distinct_labels_stay_distinct() {
        assert_eq!(tier_of("Materials", "Assembly"), None);
        assert_eq!(tier_of("Open", "Close"), None);
    }

    #[test]
    fn decoration_alone_does_not_match_everything() {
        // Both sides reduce to "", which must not count as equal.
        assert_eq!(tier_of("&", "..."), None);
    }

    // --- normalisation details ---

    #[test]
    fn non_breaking_and_ideographic_spaces_collapse() {
        assert_eq!(
            tier_of("Save\u{a0}As", "Save As"),
            Some(MatchTier::Normalized)
        );
        assert_eq!(
            tier_of("\u{3000}Save\u{3000}As", "Save As"),
            Some(MatchTier::Normalized)
        );
    }

    #[test]
    fn zero_width_characters_are_dropped() {
        assert_eq!(tier_of("Sa\u{200b}ve", "Save"), Some(MatchTier::Normalized));
    }

    #[test]
    fn a_doubled_ampersand_is_a_literal_one() {
        assert_eq!(strip_access_keys("Fish && Chips"), "Fish & Chips");
        assert_eq!(strip_access_keys("&File"), "File");
        assert_eq!(strip_access_keys("E&xit"), "Exit");
    }

    #[test]
    fn stacked_decoration_peels_completely() {
        assert_eq!(strip_affixes("&Save As...(a)"), "save as");
    }

    #[test]
    fn whitespace_only_differences_are_exact_after_trim() {
        assert_eq!(tier_of("  Save  ", "Save"), Some(MatchTier::Exact));
    }

    #[test]
    fn tiers_order_from_tightest_to_loosest() {
        assert!(MatchTier::Exact < MatchTier::Case);
        assert!(MatchTier::Case < MatchTier::Normalized);
        assert!(MatchTier::Normalized < MatchTier::Affix);
        assert!(MatchTier::Affix < MatchTier::Confusable);
    }

    // --- the OCR substring ladder ---

    #[test]
    fn ocr_substring_matches_across_case_and_composition() {
        assert_eq!(
            contains_tier("Edit Material", "Material"),
            Some(MatchTier::Exact)
        );
        assert_eq!(
            contains_tier("Edit Material", "material"),
            Some(MatchTier::Case)
        );
        assert_eq!(
            contains_tier("Ｍaterials", "materials"),
            Some(MatchTier::Normalized)
        );
    }

    #[test]
    fn ocr_substring_rejects_an_empty_needle() {
        assert_eq!(contains_tier("anything", "   "), None);
    }
}
