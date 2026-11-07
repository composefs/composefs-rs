//! Exercise splitstream parsing and both content traversal APIs.
#![no_main]

use std::io::{Seek, SeekFrom, Write};
use std::sync::LazyLock;

use composefs::fsverity::Sha256HashValue;
use composefs::splitstream::{SplitStreamReader, new_to_old_format};
use composefs::test::TestRepo;
use libfuzzer_sys::fuzz_target;

static REPO: LazyLock<TestRepo<Sha256HashValue>> = LazyLock::new(|| {
    let repo = TestRepo::new();
    repo.repo
        .ensure_object(b"external fuzz seed")
        .expect("storing seed object");
    repo
});

fn exercise(data: &[u8]) {
    let mut file = tempfile::tempfile().expect("creating input file");
    file.write_all(data).expect("writing input file");
    for cat in [true, false] {
        file.seek(SeekFrom::Start(0)).expect("rewinding input file");
        if let Ok(mut reader) = SplitStreamReader::<Sha256HashValue>::new(
            file.try_clone().expect("cloning input file"),
            None,
        ) {
            if cat {
                let _ = reader.cat(&REPO.repo, &mut std::io::sink());
            } else {
                let _ = reader.for_each_chunk(|_| Ok(()));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    // The conversion helper requires a complete new-format header and magic;
    // all other fields may be malformed and are validated by the reader.
    if data.len() >= 32 && data.starts_with(b"SplitStream") {
        exercise(&new_to_old_format(data));
    }
});
