use biome_analyze::{
    FixKind, Rule, RuleDiagnostic, RuleSource, context::RuleContext, declare_lint_rule,
};
use biome_console::markup;
use biome_diagnostics::Applicability;
use biome_js_semantic::SemanticModel;
use biome_js_syntax::{
    AnyJsCallArgument, AnyJsExpression, JsCallArguments, JsNewOrCallExpression,
    JsRegexLiteralExpression, JsSyntaxKind, JsSyntaxToken, global_identifier, inner_string_text,
    static_value::StaticValue, unescape_js_string,
};
use biome_rowan::{AstNode, AstSeparatedList, BatchMutationExt, TriviaPiece, declare_node_union};
use biome_rule_options::use_unicode_regex::UseUnicodeRegexOptions;
use biome_unicode_table::{Dispatch, lookup_byte};

use crate::{JsRuleAction, services::semantic::Semantic};

declare_lint_rule! {
    /// Enforce the use of the `u` or `v` flag for regular expressions.
    ///
    /// The `u` flag (Unicode mode) and `v` flag (Unicode Sets mode) enable proper handling
    /// of Unicode characters in regular expressions. Without these flags, regex patterns
    /// may not correctly match Unicode characters like emoji or characters outside the
    /// Basic Multilingual Plane.
    ///
    /// The `u` flag was introduced in ES2015 and enables:
    /// - Correct handling of surrogate pairs (e.g., emoji)
    /// - Unicode code point escapes (`\u{...}`)
    /// - Case-insensitive matching for Unicode characters
    ///
    /// The `v` flag was introduced in ES2024 and provides all `u` flag features plus:
    /// - Set notation in character classes
    /// - String literals in character classes
    /// - Improved Unicode property escapes
    ///
    /// Some patterns that are valid without these flags become a syntax error
    /// in Unicode mode, for example `/{/`, `/]/`, `/\a/`, `/\-/`, `/\k/`, or `/[\d-z]/`.
    /// The rule offers a migration fix to normalize these legacy Annex B patterns to valid
    /// Unicode mode equivalents.
    ///
    /// ## Examples
    ///
    /// ### Invalid
    ///
    /// ```js,expect_diagnostic
    /// /foo/;
    /// ```
    ///
    /// ```js,expect_diagnostic
    /// /foo/gi;
    /// ```
    ///
    /// ```js,expect_diagnostic
    /// new RegExp("foo");
    /// ```
    ///
    /// ```js,expect_diagnostic
    /// new RegExp("foo", "gi");
    /// ```
    ///
    /// ### Valid
    ///
    /// ```js
    /// /foo/u;
    /// /foo/v;
    /// /foo/giu;
    /// new RegExp("foo", "u");
    /// new RegExp("foo", "giv");
    /// new RegExp("foo", flags); // dynamic flags are ignored
    /// ```
    ///
    pub UseUnicodeRegex {
        version: "2.4.5",
        name: "useUnicodeRegex",
        language: "js",
        sources: &[RuleSource::Eslint("require-unicode-regexp").same()],
        recommended: false,
        fix_kind: FixKind::Safe,
    }
}

declare_node_union! {
    pub AnyRegexExpression = JsRegexLiteralExpression | JsNewOrCallExpression
}

pub enum UseUnicodeRegexState {
    Literal,
    Constructor { has_flags_arg: bool },
}

impl Rule for UseUnicodeRegex {
    type Query = Semantic<AnyRegexExpression>;
    type State = UseUnicodeRegexState;
    type Signals = Option<Self::State>;
    type Options = UseUnicodeRegexOptions;

    fn run(ctx: &RuleContext<Self>) -> Self::Signals {
        let node = ctx.query();
        let model = ctx.model();

        match node {
            AnyRegexExpression::JsRegexLiteralExpression(regex) => check_regex_literal(regex),
            AnyRegexExpression::JsNewOrCallExpression(expr) => {
                check_regexp_constructor(expr, model)
            }
        }
    }

    fn diagnostic(ctx: &RuleContext<Self>, _state: &Self::State) -> Option<RuleDiagnostic> {
        let node = ctx.query();
        Some(
            RuleDiagnostic::new(
                rule_category!(),
                node.range(),
                markup! {
                    "This regular expression is missing the "<Emphasis>"u"</Emphasis>" or "<Emphasis>"v"</Emphasis>" flag."
                },
            )
            .note(markup! {
                "Without the "<Emphasis>"u"</Emphasis>" or "<Emphasis>"v"</Emphasis>" flag, this regular expression may not correctly handle Unicode characters, "
                "such as emoji or characters outside the Basic Multilingual Plane."
            })
            .note(markup! {
                "The "<Emphasis>"u"</Emphasis>" flag enables Unicode mode which correctly handles surrogate pairs and Unicode escapes. "
                "The "<Emphasis>"v"</Emphasis>" flag (ES2024) enables Unicode Sets mode with additional features like set notation in character classes."
            }),
        )
    }

    fn action(ctx: &RuleContext<Self>, state: &Self::State) -> Option<JsRuleAction> {
        let node = ctx.query();
        let mut mutation = ctx.root().begin();

        match (node, state) {
            (
                AnyRegexExpression::JsRegexLiteralExpression(regex),
                UseUnicodeRegexState::Literal,
            ) => {
                let (pattern_text, flags_text) = regex.decompose().ok()?;
                let pattern = pattern_text.text();

                if is_valid_unicode_pattern(pattern) {
                    let token = regex.value_token().ok()?;
                    let mut text = String::new();
                    let mut leading = vec![];
                    let mut trailing = vec![];

                    for t in token.leading_trivia().pieces() {
                        text.push_str(t.text());
                        leading.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }
                    text.push_str(token.text_trimmed());
                    text.push('u');
                    for t in token.trailing_trivia().pieces() {
                        text.push_str(t.text());
                        trailing.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }

                    let new_token = JsSyntaxToken::new_detached(
                        JsSyntaxKind::JS_REGEX_LITERAL,
                        &text,
                        leading,
                        trailing,
                    );
                    mutation.replace_token(token, new_token);

                    Some(JsRuleAction::new(
                        ctx.metadata().action_category(ctx.category(), ctx.group()),
                        Applicability::Always,
                        markup! { "Add the "<Emphasis>"u"</Emphasis>" flag." }.to_owned(),
                        mutation,
                    ))
                } else if let Some(normalized) = normalize_unicode_pattern(pattern) {
                    let token = regex.value_token().ok()?;
                    let mut text = String::new();
                    let mut leading = vec![];
                    let mut trailing = vec![];

                    for t in token.leading_trivia().pieces() {
                        text.push_str(t.text());
                        leading.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }
                    text.push('/');
                    text.push_str(&normalized);
                    text.push('/');
                    text.push_str(flags_text.text());
                    text.push('u');
                    for t in token.trailing_trivia().pieces() {
                        text.push_str(t.text());
                        trailing.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }

                    let new_token = JsSyntaxToken::new_detached(
                        JsSyntaxKind::JS_REGEX_LITERAL,
                        &text,
                        leading,
                        trailing,
                    );
                    mutation.replace_token(token, new_token);

                    Some(JsRuleAction::new(
                        ctx.metadata().action_category(ctx.category(), ctx.group()),
                        Applicability::MaybeIncorrect,
                        markup! { "Migrate legacy pattern to Unicode mode and add the "<Emphasis>"u"</Emphasis>" flag." }.to_owned(),
                        mutation,
                    ))
                } else {
                    None
                }
            }
            (
                AnyRegexExpression::JsNewOrCallExpression(expr),
                UseUnicodeRegexState::Constructor { has_flags_arg },
            ) => {
                if !has_flags_arg {
                    // No flags argument - skip auto-fix (would need to add argument)
                    return None;
                }

                let (_, arguments) = parse_regexp_node(expr)?;
                let args = arguments.args();
                let pattern_arg = args.iter().next()?.ok()?;
                let flags_arg = args.iter().nth(1)?.ok()?;

                let AnyJsCallArgument::AnyJsExpression(pattern_expr) = pattern_arg else {
                    return None;
                };
                let pattern_expr = pattern_expr.omit_parentheses();
                let (pattern_text, pattern_token, pattern_quote) =
                    match pattern_expr.as_static_value()? {
                        StaticValue::EmptyString(token) => {
                            let quote = token.text_trimmed().chars().next()?;
                            if quote != '"' && quote != '\'' {
                                return None;
                            }
                            (String::new(), token, quote)
                        }
                        StaticValue::String(token)
                            if token.kind() == JsSyntaxKind::JS_STRING_LITERAL =>
                        {
                            let text = inner_string_text(&token);
                            if has_legacy_octal_escape(text.text()) {
                                return None;
                            }
                            let unescaped = unescape_js_string(text);
                            if unescaped.contains('\u{fffd}') {
                                return None;
                            }
                            let quote = token.text_trimmed().chars().next()?;
                            if quote != '"' && quote != '\'' {
                                return None;
                            }
                            (unescaped.to_string(), token, quote)
                        }
                        _ => return None,
                    };

                let AnyJsCallArgument::AnyJsExpression(flags_expr) = flags_arg else {
                    return None;
                };
                let flags_token = flags_expr.syntax().first_token()?;
                let flags_token_text = flags_token.text();
                let flags_quote = flags_token_text.chars().next()?;
                if flags_quote != '"' && flags_quote != '\'' {
                    return None;
                }
                let static_val = flags_expr.as_static_value()?;
                let flags_text = static_val.as_string_constant()?;

                let new_flags = format!("{flags_quote}{flags_text}u{flags_quote}");

                let mut flags_mut_text = String::new();
                let mut flags_leading = vec![];
                let mut flags_trailing = vec![];

                for t in flags_token.leading_trivia().pieces() {
                    flags_mut_text.push_str(t.text());
                    flags_leading.push(TriviaPiece::new(t.kind(), t.text_len()));
                }
                flags_mut_text.push_str(&new_flags);
                for t in flags_token.trailing_trivia().pieces() {
                    flags_mut_text.push_str(t.text());
                    flags_trailing.push(TriviaPiece::new(t.kind(), t.text_len()));
                }

                let new_flags_token = JsSyntaxToken::new_detached(
                    JsSyntaxKind::JS_STRING_LITERAL,
                    &flags_mut_text,
                    flags_leading,
                    flags_trailing,
                );
                mutation.replace_token(flags_token, new_flags_token);

                if is_valid_unicode_pattern(&pattern_text) {
                    Some(JsRuleAction::new(
                        ctx.metadata().action_category(ctx.category(), ctx.group()),
                        Applicability::Always,
                        markup! { "Add the "<Emphasis>"u"</Emphasis>" flag." }.to_owned(),
                        mutation,
                    ))
                } else if let Some(normalized) = normalize_unicode_pattern(&pattern_text) {
                    let mut escaped_pattern = String::new();
                    for ch in normalized.chars() {
                        if ch == '\\' {
                            escaped_pattern.push_str("\\\\");
                        } else if ch == pattern_quote {
                            escaped_pattern.push('\\');
                            escaped_pattern.push(pattern_quote);
                        } else {
                            escaped_pattern.push(ch);
                        }
                    }
                    let new_pattern =
                        format!("{pattern_quote}{escaped_pattern}{pattern_quote}");

                    let mut pattern_mut_text = String::new();
                    let mut pattern_leading = vec![];
                    let mut pattern_trailing = vec![];

                    for t in pattern_token.leading_trivia().pieces() {
                        pattern_mut_text.push_str(t.text());
                        pattern_leading.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }
                    pattern_mut_text.push_str(&new_pattern);
                    for t in pattern_token.trailing_trivia().pieces() {
                        pattern_mut_text.push_str(t.text());
                        pattern_trailing.push(TriviaPiece::new(t.kind(), t.text_len()));
                    }

                    let new_pattern_token = JsSyntaxToken::new_detached(
                        JsSyntaxKind::JS_STRING_LITERAL,
                        &pattern_mut_text,
                        pattern_leading,
                        pattern_trailing,
                    );
                    mutation.replace_token(pattern_token, new_pattern_token);

                    Some(JsRuleAction::new(
                        ctx.metadata().action_category(ctx.category(), ctx.group()),
                        Applicability::MaybeIncorrect,
                        markup! { "Migrate legacy pattern to Unicode mode and add the "<Emphasis>"u"</Emphasis>" flag." }.to_owned(),
                        mutation,
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn check_regex_literal(regex: &JsRegexLiteralExpression) -> Option<UseUnicodeRegexState> {
    let (_, flags) = regex.decompose().ok()?;
    let flags_text = flags.text();

    if flags_text.contains('u') || flags_text.contains('v') {
        None
    } else {
        Some(UseUnicodeRegexState::Literal)
    }
}

fn check_regexp_constructor(
    expr: &JsNewOrCallExpression,
    model: &SemanticModel,
) -> Option<UseUnicodeRegexState> {
    let (callee, arguments) = parse_regexp_node(expr)?;

    // Check if callee is global RegExp
    if !is_regexp_object(&callee, model) {
        return None;
    }

    let args = arguments.args();

    // Check if first argument is spread - cannot statically analyze
    let first_arg = args.iter().next();
    if matches!(first_arg, Some(Ok(AnyJsCallArgument::JsSpread(_)))) {
        return None;
    }

    // Need at least pattern argument
    if args.is_empty() {
        return None;
    }

    // Check flags argument (second argument)
    let flags_arg = args.iter().nth(1);

    match flags_arg {
        Some(Ok(AnyJsCallArgument::AnyJsExpression(flags_expr))) => {
            // Try to get static value of flags
            match flags_expr.as_static_value() {
                Some(val) => {
                    // Static flags - check if u or v is present
                    let flags_text = val.as_string_constant()?;
                    if flags_text.contains('u') || flags_text.contains('v') {
                        None
                    } else {
                        Some(UseUnicodeRegexState::Constructor {
                            has_flags_arg: true,
                        })
                    }
                }
                None => {
                    // Dynamic flags (variable) - ignore
                    None
                }
            }
        }
        Some(Ok(AnyJsCallArgument::JsSpread(_))) => {
            // Spread argument - ignore
            None
        }
        Some(Err(_)) => None,
        None => {
            // No flags argument at all
            Some(UseUnicodeRegexState::Constructor {
                has_flags_arg: false,
            })
        }
    }
}

fn is_regexp_object(expr: &AnyJsExpression, model: &SemanticModel) -> bool {
    match expr
        .clone()
        .omit_parentheses()
        .as_any_global_identifier_expression()
        .and_then(|e| global_identifier(&e))
    {
        Some((reference, name)) => match model.binding(&reference) {
            Some(_) if !reference.is_global_this() && !reference.has_name("window") => false,
            _ => name.text() == "RegExp",
        },
        None => false,
    }
}

fn parse_regexp_node(node: &JsNewOrCallExpression) -> Option<(AnyJsExpression, JsCallArguments)> {
    match node {
        JsNewOrCallExpression::JsNewExpression(node) => {
            let callee = node.callee().ok()?;
            let args = node.arguments()?;
            Some((callee, args))
        }
        JsNewOrCallExpression::JsCallExpression(node) => {
            let callee = node.callee().ok()?;
            let args = node.arguments().ok()?;
            Some((callee, args))
        }
    }
}

fn is_digit(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| matches!(lookup_byte(byte), Dispatch::ZER | Dispatch::DIG))
}

/// Returns whether the raw text of a string literal contains a legacy octal
/// escape (`\1`, `\01`, `\173`) or a non-octal decimal escape (`\8`, `\9`).
fn has_legacy_octal_escape(text: &str) -> bool {
    let mut bytes = text.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            match bytes.next().map(lookup_byte) {
                Some(Dispatch::DIG) => return true,
                Some(Dispatch::ZER) if is_digit(bytes.peek().copied()) => return true,
                _ => {}
            }
        }
    }
    false
}

/// Conservatively checks, in a single pass, that a pattern valid without the
/// `u` flag is also valid with it.
///
/// Unicode mode doesn't allow the web compatibility syntax of Annex B, such as
/// lone quantifier brackets (`/{/`, `/]/`), identity escapes (`/\a/`), or
/// character class escapes used as range endpoints (`/[\d-z]/`).
/// When in doubt, this function returns `false`.
fn is_valid_unicode_pattern(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let at = |index: usize| bytes.get(index).copied();
    let skip_digits = |mut index: usize| {
        while is_digit(at(index)) {
            index += 1;
        }
        index
    };

    // Backreferences may precede their group, so they are checked at the end.
    let mut capturing_groups = 0;
    let mut max_backreference = 0;
    let mut has_named_groups = false;
    let mut has_named_backreference = false;
    // One bit per open group, set for lookarounds, above a sentinel bit.
    let mut groups = 1u128;
    // Whether the current character class contains an endpoint that may
    // change or be invalid in Unicode mode, and whether it contains a range.
    let mut in_class = false;
    let mut class_has_unsafe_endpoint = false;
    let mut class_has_range = false;
    let mut class_start = 0;
    let mut i = 0;
    while let Some(byte) = at(i) {
        if byte == b'\\' {
            match at(i + 1) {
                Some(b'd' | b'D' | b's' | b'S' | b'w' | b'W') => {
                    class_has_unsafe_endpoint = true;
                    i += 1;
                }
                Some(
                    b'^' | b'$' | b'\\' | b'.' | b'*' | b'+' | b'?' | b'(' | b')' | b'[' | b']'
                    | b'{' | b'}' | b'|' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' | b'v',
                ) => i += 1,
                Some(b'B') if !in_class => i += 1,
                Some(b'-') if in_class => i += 1,
                Some(b'k') if !in_class => {
                    has_named_backreference = true;
                    i += 1;
                }
                Some(b'0') if !is_digit(at(i + 2)) => i += 1,
                // A decimal escape is an octal escape without the `u` flag when
                // it's in a class or refers to a missing group.
                Some(b'1'..=b'9') if !in_class => {
                    let mut group = 0usize;
                    while is_digit(at(i + 1)) {
                        i += 1;
                        group = group
                            .saturating_mul(10)
                            .saturating_add(usize::from(bytes[i] - b'0'));
                    }
                    max_backreference = max_backreference.max(group);
                }
                Some(b'c') if at(i + 2).is_some_and(|byte| byte.is_ascii_alphabetic()) => i += 2,
                Some(b'x')
                    if bytes
                        .get(i + 2..i + 4)
                        .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) =>
                {
                    i += 3;
                }
                Some(b'u') => {
                    let value = bytes.get(i + 2..i + 6).and_then(|hex| {
                        hex.iter().try_fold(0, |value, &digit| {
                            Some(value * 16 + char::from(digit).to_digit(16)?)
                        })
                    });
                    // Surrogate pairs are combined into a single code point in Unicode mode.
                    match value {
                        Some(value) if !(0xd800..=0xdfff).contains(&value) => i += 5,
                        _ => return false,
                    }
                }
                _ => return false,
            }
        } else if in_class {
            match byte {
                b']' => {
                    if class_has_unsafe_endpoint && class_has_range {
                        return false;
                    }
                    in_class = false;
                }
                b'-' if i > class_start && at(i + 1) != Some(b']') => class_has_range = true,
                // The first byte of a character outside the BMP
                0xf0.. => class_has_unsafe_endpoint = true,
                _ => {}
            }
        } else {
            match byte {
                b'[' => {
                    in_class = true;
                    class_has_unsafe_endpoint = false;
                    class_has_range = false;
                    class_start = if at(i + 1) == Some(b'^') { i + 2 } else { i + 1 };
                    i = class_start - 1;
                }
                b'(' => {
                    let is_lookaround = match (at(i + 1), at(i + 2), at(i + 3)) {
                        (Some(b'?'), Some(b':'), _) => false,
                        (Some(b'?'), Some(b'=' | b'!'), _)
                        | (Some(b'?'), Some(b'<'), Some(b'=' | b'!')) => true,
                        (Some(b'?'), Some(b'<'), _) => {
                            let mut end = i + 3;
                            while at(end).is_some_and(|byte| {
                                matches!(
                                    lookup_byte(byte),
                                    Dispatch::IDT | Dispatch::DOL | Dispatch::ZER | Dispatch::DIG
                                )
                            }) {
                                end += 1;
                            }
                            if end == i + 3 || at(end) != Some(b'>') {
                                return false;
                            }
                            has_named_groups = true;
                            capturing_groups += 1;
                            i = end;
                            false
                        }
                        // Modifiers and other extensions
                        (Some(b'?'), _, _) => return false,
                        _ => {
                            capturing_groups += 1;
                            false
                        }
                    };
                    if groups.leading_zeros() == 0 {
                        return false;
                    }
                    groups = groups << 1 | u128::from(is_lookaround);
                }
                b')' => {
                    let is_lookaround = groups == 1 || groups & 1 == 1;
                    groups = (groups >> 1).max(1);
                    // Lookaheads can be quantified only without the `u` flag.
                    if is_lookaround && matches!(at(i + 1), Some(b'*' | b'+' | b'?' | b'{')) {
                        return false;
                    }
                }
                b'{' => {
                    // A brace must start a valid quantifier in Unicode mode.
                    let min_end = skip_digits(i + 1);
                    let end = if at(min_end) == Some(b',') {
                        skip_digits(min_end + 1)
                    } else {
                        min_end
                    };
                    if min_end == i + 1 || at(end) != Some(b'}') {
                        return false;
                    }
                    i = end;
                }
                b'}' | b']' => return false,
                _ => {}
            }
        }
        i += 1;
    }
    !in_class
        && max_backreference <= capturing_groups
        && (has_named_groups || !has_named_backreference)
}

/// Transforms Annex B legacy patterns into valid Unicode equivalents:
/// - Escapes lone `{` when not a valid quantifier: `/{/` -> `/\{/`
/// - Escapes lone `]`: `/]/` -> `/\]/`
/// - Escapes lone `}`: `/}/` -> `/\}/`
/// - Replaces invalid identity escapes outside character classes: `/\-/` -> `/-/`, `/\a/` -> `/a/`, `/\k/` -> `/k/`
/// - Inside character classes, escapes `-` when used next to class escape endpoints: e.g. `[\d-z]` -> `[\d\-z]`
/// - Validates that `is_valid_unicode_pattern(&normalized)` is `true`.
fn normalize_unicode_pattern(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let at = |index: usize| bytes.get(index).copied();
    let skip_digits = |mut index: usize| {
        while is_digit(at(index)) {
            index += 1;
        }
        index
    };

    let mut normalized = String::with_capacity(pattern.len() + 8);
    let mut in_class = false;
    let mut class_start = 0;
    let mut prev_was_class_escape = false;
    let mut i = 0;

    while let Some(byte) = at(i) {
        if byte == b'\\' {
            let next_byte = at(i + 1);
            if in_class {
                match next_byte {
                    Some(b'd' | b'D' | b's' | b'S' | b'w' | b'W') => {
                        normalized.push('\\');
                        normalized.push(next_byte.unwrap() as char);
                        prev_was_class_escape = true;
                        i += 2;
                        continue;
                    }
                    Some(b'-') => {
                        normalized.push_str(r"\-");
                        prev_was_class_escape = false;
                        i += 2;
                        continue;
                    }
                    Some(
                        b @ (b'^' | b'\\' | b'[' | b']' | b'b' | b'f' | b'n' | b'r' | b't' | b'v'),
                    ) => {
                        normalized.push('\\');
                        normalized.push(b as char);
                        prev_was_class_escape = false;
                        i += 2;
                        continue;
                    }
                    Some(b'0') if !is_digit(at(i + 2)) => {
                        normalized.push_str(r"\0");
                        prev_was_class_escape = false;
                        i += 2;
                        continue;
                    }
                    Some(b'c') if at(i + 2).is_some_and(|c| c.is_ascii_alphabetic()) => {
                        normalized.push('\\');
                        normalized.push('c');
                        normalized.push(at(i + 2).unwrap() as char);
                        prev_was_class_escape = false;
                        i += 3;
                        continue;
                    }
                    Some(b'x')
                        if bytes
                            .get(i + 2..i + 4)
                            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) =>
                    {
                        normalized.push('\\');
                        normalized.push('x');
                        normalized.push(at(i + 2).unwrap() as char);
                        normalized.push(at(i + 3).unwrap() as char);
                        prev_was_class_escape = false;
                        i += 4;
                        continue;
                    }
                    Some(b'u') => {
                        normalized.push('\\');
                        normalized.push('u');
                        prev_was_class_escape = false;
                        i += 2;
                        continue;
                    }
                    Some(b) => {
                        // Invalid identity escape inside class: strip the backslash
                        normalized.push(b as char);
                        prev_was_class_escape = false;
                        i += 2;
                        continue;
                    }
                    None => {
                        normalized.push('\\');
                        i += 1;
                        continue;
                    }
                }
            } else {
                match next_byte {
                    Some(
                        b @ (b'^'
                        | b'$'
                        | b'\\'
                        | b'.'
                        | b'*'
                        | b'+'
                        | b'?'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'|'
                        | b'/'
                        | b'b'
                        | b'B'
                        | b'f'
                        | b'n'
                        | b'r'
                        | b't'
                        | b'v'
                        | b'd'
                        | b'D'
                        | b's'
                        | b'S'
                        | b'w'
                        | b'W'),
                    ) => {
                        normalized.push('\\');
                        normalized.push(b as char);
                        i += 2;
                        continue;
                    }
                    Some(b'0') if !is_digit(at(i + 2)) => {
                        normalized.push_str(r"\0");
                        i += 2;
                        continue;
                    }
                    Some(b'c') if at(i + 2).is_some_and(|c| c.is_ascii_alphabetic()) => {
                        normalized.push('\\');
                        normalized.push('c');
                        normalized.push(at(i + 2).unwrap() as char);
                        i += 3;
                        continue;
                    }
                    Some(b'x')
                        if bytes
                            .get(i + 2..i + 4)
                            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) =>
                    {
                        normalized.push('\\');
                        normalized.push('x');
                        normalized.push(at(i + 2).unwrap() as char);
                        normalized.push(at(i + 3).unwrap() as char);
                        i += 4;
                        continue;
                    }
                    Some(b'u') => {
                        normalized.push('\\');
                        normalized.push('u');
                        i += 2;
                        continue;
                    }
                    Some(b @ b'1'..=b'9') => {
                        normalized.push('\\');
                        normalized.push(b as char);
                        i += 2;
                        continue;
                    }
                    Some(b'k') if at(i + 2) == Some(b'<') => {
                        normalized.push_str(r"\k<");
                        i += 3;
                        continue;
                    }
                    Some(b) => {
                        // Invalid identity escape outside class: strip the backslash
                        normalized.push(b as char);
                        i += 2;
                        continue;
                    }
                    None => {
                        normalized.push('\\');
                        i += 1;
                        continue;
                    }
                }
            }
        } else if in_class {
            match byte {
                b']' => {
                    in_class = false;
                    prev_was_class_escape = false;
                    normalized.push(']');
                }
                b'-' => {
                    let is_range_start = i > class_start && at(i + 1) != Some(b']');
                    let next_is_class_escape = at(i + 1) == Some(b'\\')
                        && matches!(at(i + 2), Some(b'd' | b'D' | b's' | b'S' | b'w' | b'W'));

                    if is_range_start && (prev_was_class_escape || next_is_class_escape) {
                        normalized.push_str(r"\-");
                    } else {
                        normalized.push('-');
                    }
                    prev_was_class_escape = false;
                }
                _ => {
                    prev_was_class_escape = false;
                    normalized.push(byte as char);
                }
            }
        } else {
            match byte {
                b'[' => {
                    in_class = true;
                    prev_was_class_escape = false;
                    class_start = if at(i + 1) == Some(b'^') { i + 2 } else { i + 1 };
                    normalized.push('[');
                }
                b'{' => {
                    let min_end = skip_digits(i + 1);
                    let end = if at(min_end) == Some(b',') {
                        skip_digits(min_end + 1)
                    } else {
                        min_end
                    };
                    if min_end == i + 1 || at(end) != Some(b'}') {
                        normalized.push_str(r"\{");
                    } else {
                        normalized.push_str(&pattern[i..=end]);
                        i = end;
                    }
                }
                b'}' => {
                    normalized.push_str(r"\}");
                }
                b']' => {
                    normalized.push_str(r"\]");
                }
                _ => {
                    normalized.push(byte as char);
                }
            }
        }
        i += 1;
    }

    if is_valid_unicode_pattern(&normalized) {
        Some(normalized)
    } else {
        None
    }
}
