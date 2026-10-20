// The streaming limit is independent of the earlier metadata length check.
mod cache_read_bound_tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Read, Seek};
    use std::rc::Rc;

    struct CountedStream {
        remaining: usize,
        returned: Rc<Cell<usize>>,
    }

    impl Read for CountedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.remaining.min(buf.len());
            buf[..count].fill(b'x');
            self.remaining -= count;
            self.returned.set(self.returned.get() + count);
            Ok(count)
        }
    }

    #[test]
    fn counted_stream_stops_at_one_sentinel_before_oversize_refusal() {
        let returned = Rc::new(Cell::new(0));
        let stream = CountedStream {
            remaining: CACHE_MAX_FILE_SIZE as usize + 8192,
            returned: Rc::clone(&returned),
        };
        let result = read_cache_bytes(stream, 0);
        assert_eq!(
            returned.get(),
            CACHE_MAX_FILE_SIZE as usize + 1,
            "streaming cache read must stop after exactly one oversize sentinel"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "parse cache exceeds maximum file size");
    }

    #[test]
    fn opened_file_growth_after_metadata_is_bounded_and_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opened-cache.bin");
        std::fs::write(&path, []).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let observed_len = file.metadata().unwrap().len();
        assert_eq!(observed_len, 0);
        // Grow the same inode deterministically after observing its admission length.
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        use std::io::Write as _;
        writer
            .write_all(&vec![b'x'; CACHE_MAX_FILE_SIZE as usize + 2])
            .unwrap();
        drop(writer);
        assert!(file.metadata().unwrap().len() > observed_len);
        let result = read_cache_bytes(&mut file, observed_len);
        assert_eq!(file.stream_position().unwrap(), CACHE_MAX_FILE_SIZE + 1);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn exact_stream_limit_is_accepted_but_sentinel_content_is_refused() {
        let exact = vec![b'x'; CACHE_MAX_FILE_SIZE as usize];
        let loaded = read_cache_bytes(std::io::Cursor::new(&exact), 0).unwrap();
        assert_eq!(loaded, exact);
        let oversized = vec![b'x'; CACHE_MAX_FILE_SIZE as usize + 1];
        let result = read_cache_bytes(std::io::Cursor::new(oversized), 0);
        assert!(
            result.is_err(),
            "streaming cache sentinel must be rejected before payload decode"
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
