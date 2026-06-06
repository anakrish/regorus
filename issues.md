# Known Issues

## Lexer subtraction and slicing panics (`src/lexer.rs`)

- `Source::message` subtracts 1 from both the `col` and `line` arguments (`col as usize - 1`, `self.line(line - 1)`) without validating that callers supplied 1-based coordinates. Passing a zero-based span causes an immediate `attempt to subtract with overflow` panic instead of returning a diagnostic. Guard the subtraction with `saturating_sub` or reject spans where `line == 0 || col == 0`.
- `Lexer::read_string` validates literals with `self.source.contents()[start - 1..end]`. `start` is captured after advancing past the opening quote, so any iterator desynchronization that sets `start == 0` results in the same panic before the lexer can emit an "unmatched quote" error. Capture the opening offset before consuming it or use `checked_sub(1)` and convert `None` into a lexer error.
- `read_raw_string`, `read_string`, and `read_single_quoted_string` all construct spans via `end as u32 - 1`. Those paths assume the closing delimiter was seen; if a future regression lets an unterminated literal reach the span construction, they will panic. Use `end.checked_sub(1)` and report an error when the subtraction underflows.
- Many helper types (`Span::text`, `SourceStr::text`, etc.) slice with the provided offsets without asserting `start <= end`. Bugs elsewhere still manifest as slicing panics. Consider adding debug assertions or validating spans when they are created.
