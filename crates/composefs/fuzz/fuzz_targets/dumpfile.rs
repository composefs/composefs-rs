//! Parse a UTF-8 dumpfile line and roundtrip through the entry writer.
#![no_main]

use composefs::dumpfile_parse::Entry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(entry) = Entry::parse(data) {
        let written = entry.to_string();
        let reparsed = Entry::parse(&written).expect("writer output must parse");
        assert_eq!(entry, reparsed);
    }
});
