use crate::FormatEmbedded;
use crate::prelude::*;
use biome_formatter::{CstFormatContext, VecBuffer, normalize_newlines, write};
use biome_html_syntax::{HtmlSyntaxToken, VueVForValue, VueVForValueFields};

#[derive(Debug, Clone, Default)]
pub(crate) struct FormatVueVForValue;
impl FormatNodeRule<VueVForValue> for FormatVueVForValue {
    fn fmt_fields(&self, node: &VueVForValue, f: &mut HtmlFormatter) -> FormatResult<()> {
        let VueVForValueFields {
            l_quote,
            binding,
            operator,
            expression,
            r_quote,
        } = node.as_fields();
        let binding = binding?;
        let expression = expression?;
        let expression_token = expression.html_literal_token()?;
        let is_embedded = f.context().should_delegate_fmt_embedded_nodes()
            && f.context().is_embedded_node_range(expression.range());

        // Like other attribute values, the value is written between double
        // quotes, and the expression formatted as JavaScript uses single quotes
        // for its strings. The value keeps its own quotes when a double quote
        // inside it can't be rewritten: in a binding, which is only possible
        // for invalid code, or in an expression that isn't formatted as
        // JavaScript.
        let keeps_quotes = binding.syntax().text_trimmed().contains_char('"')
            || (!is_embedded && expression_token.text().contains('"'));

        // The expression is written here rather than by its own rule, which
        // would hand it to the JavaScript formatter even when the value keeps
        // its own quotes.
        f.context()
            .comments()
            .mark_suppression_checked(expression.syntax());

        if keeps_quotes {
            return write!(
                f,
                [
                    l_quote.format(),
                    binding.format(),
                    space(),
                    operator.format(),
                    space(),
                    format_replaced(
                        &expression_token,
                        &format_expression_text(&expression_token, false)
                    ),
                    r_quote.format()
                ]
            );
        }

        write!(
            f,
            [
                format_replaced(&l_quote?, &token("\"")),
                binding.format(),
                space(),
                operator.format(),
                space(),
            ]
        )?;
        if is_embedded {
            // The expression keeps its text when it can't be formatted as
            // JavaScript, with its double quotes escaped so they don't end the
            // value.
            let mut buffer = VecBuffer::new(f.state_mut());
            write!(buffer, [format_expression_text(&expression_token, true)])?;
            let embedded = FormatEmbedded {
                range: expression.range(),
                content: Interned::new(buffer.into_vec()),
            };
            write!(f, [format_replaced(&expression_token, &embedded)])?;
        } else {
            write!(
                f,
                [format_replaced(
                    &expression_token,
                    &format_expression_text(&expression_token, false)
                )]
            )?;
        }
        write!(f, [format_replaced(&r_quote?, &token("\""))])
    }
}

/// Formats the text of a `v-for` expression as it's written, without the
/// surrounding whitespace, optionally escaping its double quotes as `&quot;`.
fn format_expression_text(
    token: &HtmlSyntaxToken,
    escape_quotes: bool,
) -> impl Format<HtmlFormatContext> {
    format_with(move |f| {
        let trimmed_text = token.text().trim();
        let normalized_text = normalize_newlines(trimmed_text, ['\r']);
        let content = if escape_quotes {
            normalized_text.replace('"', "&quot;").into()
        } else {
            normalized_text
        };
        write!(f, [text(&content, Some(token.text_range().start()))])
    })
}
