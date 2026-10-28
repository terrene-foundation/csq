// Cache-local provenance tests, not an owner schema or freshness claim.
#[cfg(test)]
mod rule_origin_cache_tests {
    use super::*;

    fn snapshot(root: &Path) -> ParsedCocWithRuleOrigins {
        let coc = root.join(".coc");
        std::fs::create_dir_all(coc.join("rules")).unwrap();
        std::fs::write(coc.join("COC.md"), "---\ncoc.version: 1.0.0\n---\n").unwrap();
        std::fs::write(
            coc.join("rules/selected-name.md"),
            "---\nid: RULE-X\n---\nSNAPSHOT\n",
        )
        .unwrap();
        super::super::super::parser::parse_coc_dir_with_rule_origins(
            &coc,
            super::super::super::types::CocSource::LegacyClaude,
        )
        .unwrap()
    }

    fn payload_of(parsed: &ParsedCocWithRuleOrigins) -> ParsedCachePayload {
        ParsedCachePayload {
            set: parsed.set.clone(),
            rule_origins: Some(
                parsed
                    .rule_origins
                    .iter()
                    .map(|(id, origin)| {
                        (
                            id.clone(),
                            CachedRuleOrigin {
                                relative_path: origin.relative_path.clone(),
                                raw_sha256: origin.raw_sha256,
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn richer_cache_roundtrips_and_compatibility_writer_marks_origins_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = snapshot(dir.path());
        let key = lock_sha256(b"roundtrip");
        write_parsed_cache_with_rule_origins(dir.path(), &key, &parsed).unwrap();
        assert_eq!(
            read_parsed_cache_with_rule_origins(dir.path(), &key).unwrap(),
            parsed
        );
        assert_eq!(read_parsed_cache(dir.path(), &key).unwrap(), parsed.set);
        write_parsed_cache(dir.path(), &key, &parsed.set).unwrap();
        assert_eq!(read_parsed_cache(dir.path(), &key).unwrap(), parsed.set);
        assert!(
            read_parsed_cache_with_rule_origins(dir.path(), &key).is_none(),
            "compatibility writer must not invent selected-read origins"
        );
    }

    #[test]
    fn richer_reader_rejects_missing_partial_extra_and_nonlocal_origins() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = snapshot(dir.path());
        let key = lock_sha256(b"invalid-origins");
        for case in [
            "missing",
            "partial",
            "extra",
            "absolute",
            "parent",
            "inner-parent",
            "other-kind",
            "nested",
            "non-md",
        ] {
            let mut payload = payload_of(&parsed);
            let id = RuleId::parse("RULE-X").unwrap();
            match case {
                "missing" => payload.rule_origins = None,
                "partial" => payload.rule_origins.as_mut().unwrap().clear(),
                "extra" => {
                    payload.rule_origins.as_mut().unwrap().insert(
                        RuleId::parse("RULE-EXTRA").unwrap(),
                        CachedRuleOrigin {
                            relative_path: PathBuf::from("rules/extra.md"),
                            raw_sha256: [9; 32],
                        },
                    );
                }
                other => {
                    let path = match other {
                        "absolute" => dir.path().join("rules/selected-name.md"),
                        "parent" => PathBuf::from("../rules/selected-name.md"),
                        "inner-parent" => PathBuf::from("rules/../selected-name.md"),
                        "other-kind" => PathBuf::from("agents/selected-name.md"),
                        "nested" => PathBuf::from("rules/nested/selected-name.md"),
                        "non-md" => PathBuf::from("rules/selected-name.txt"),
                        _ => unreachable!(),
                    };
                    payload
                        .rule_origins
                        .as_mut()
                        .unwrap()
                        .get_mut(&id)
                        .unwrap()
                        .relative_path = path;
                }
            }
            // Malformed payload is deliberately written below the validating public writer.
            write_cache_payload(dir.path(), &key, &payload).unwrap();
            assert!(
                read_parsed_cache_with_rule_origins(dir.path(), &key).is_none(),
                "incomplete or nonlocal cached origins must miss: {case}"
            );
            assert_eq!(read_parsed_cache(dir.path(), &key).unwrap(), parsed.set);
        }
    }

    #[test]
    fn format_one_payload_is_a_miss_and_does_not_guess_paths() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = snapshot(dir.path());
        let key = lock_sha256(b"old-format");
        std::fs::create_dir_all(cache_dir(dir.path())).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CACHE_MAGIC);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&csq_version_padded());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&encode_length_prefixed(
            &serde_json::to_vec(&parsed.set).unwrap(),
        ));
        std::fs::write(cache_file(dir.path(), &key), bytes).unwrap();
        assert!(read_parsed_cache_with_rule_origins(dir.path(), &key).is_none());
        assert!(read_parsed_cache(dir.path(), &key).is_none());
    }
}
