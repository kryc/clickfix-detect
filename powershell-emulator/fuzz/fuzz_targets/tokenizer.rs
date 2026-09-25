#![no_main]

use libfuzzer_sys::fuzz_target;
use powershell_emulator::tokenizer::tokenize;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };

    let tokenization = tokenize(source);
    let mut cursor = 0;
    for token in tokenization.tokens {
        assert_eq!(token.span.start, cursor);
        assert!(token.span.start < token.span.end);
        assert!(token.span.end <= source.len());
        assert!(source.is_char_boundary(token.span.start));
        assert!(source.is_char_boundary(token.span.end));
        let _ = token.text(source);
        cursor = token.span.end;
    }
    assert_eq!(cursor, source.len());

    for diagnostic in tokenization.diagnostics {
        assert!(diagnostic.span.start <= diagnostic.span.end);
        assert!(diagnostic.span.end <= source.len());
        assert!(source.is_char_boundary(diagnostic.span.start));
        assert!(source.is_char_boundary(diagnostic.span.end));
    }
});
