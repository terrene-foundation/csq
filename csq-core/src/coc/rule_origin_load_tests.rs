// Rich loader snapshot provenance fixtures; warm does not mean current disk.
#[cfg(test)]
mod rule_origin_load_tests {
    use super::*;

    fn install(root: &Path) -> (Vec<u8>, PathBuf, String) {
        let lock = b"{\"fixture\":\"origin-cache\"}".to_vec();
        build_coc_dir(root, &lock);
        let rules = root.join(".coc/rules");
        fs::write(
            rules.join("a-losing.md"),
            "---\nid: RULE-SAME\nprecedence: 1\n---\nLOSING\n",
        )
        .unwrap();
        let winner = "---\nid: RULE-SAME\nprecedence: 9\n---\nFIRST-SNAPSHOT\n".to_string();
        let path = rules.join("z-unrelated-winner.md");
        fs::write(&path, &winner).unwrap();
        (lock, path, winner)
    }

    fn tamper(root: &Path, key: &[u8; 32], edit: impl FnOnce(&mut serde_json::Value)) {
        let path = cache::cache_file(root, key);
        let bytes = fs::read(&path).unwrap();
        let mut payload: serde_json::Value = serde_json::from_slice(&bytes[67..]).unwrap();
        edit(&mut payload);
        let json = serde_json::to_vec(&payload).unwrap();
        let mut changed = bytes[..59].to_vec();
        changed.extend_from_slice(&(json.len() as u64).to_le_bytes());
        changed.extend_from_slice(&json);
        fs::write(path, changed).unwrap();
    }

    #[test]
    fn cold_and_warm_preserve_one_selected_snapshot_with_historical_warm_origins() {
        let dir = tempfile::tempdir().unwrap();
        let (_lock, path, first_bytes) = install(dir.path());
        let base = dir.path().join("isolated-base");
        let first = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
        assert_eq!(first.warmth, Warmth::Cold);
        let id = RuleId::parse("RULE-SAME").unwrap();
        let origin = &first.rule_origins.as_ref().unwrap()[&id];
        assert_eq!(
            origin.relative_path,
            PathBuf::from("rules/z-unrelated-winner.md")
        );
        assert_eq!(
            origin.raw_sha256,
            cache::lock_sha256(first_bytes.as_bytes())
        );
        assert_eq!(first.outcome.set.rules[&id].body.trim(), "FIRST-SNAPSHOT");
        let changed = first_bytes.replace("FIRST-SNAPSHOT", "NEW-DISK-SNAPSHOT");
        fs::write(&path, &changed).unwrap();
        let warm = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
        assert_eq!(
            warm.warmth,
            Warmth::Warm,
            "complete origins must survive the cold cache write for a warm reload"
        );
        assert_eq!(warm.outcome.set, first.outcome.set);
        assert_eq!(
            warm.rule_origins, first.rule_origins,
            "warm loaded provenance must retain the exact selected parsed snapshot"
        );
        assert_ne!(
            warm.rule_origins.as_ref().unwrap()[&id].raw_sha256,
            cache::lock_sha256(changed.as_bytes())
        );
        let compatibility = load_with_cache(dir.path(), &base, true).unwrap();
        assert_eq!(compatibility.warmth, Warmth::Warm);
        assert_eq!(compatibility.outcome.set, warm.outcome.set);
        let disabled = load_with_rule_origins(dir.path(), &base).unwrap();
        assert_eq!(disabled.warmth, Warmth::Cold);
        assert_eq!(
            disabled.outcome.set.rules[&id].body.trim(),
            "NEW-DISK-SNAPSHOT"
        );
        assert_eq!(
            disabled.rule_origins.as_ref().unwrap()[&id].raw_sha256,
            cache::lock_sha256(changed.as_bytes())
        );
        assert_eq!(
            load_with_cache_and_rule_origins(dir.path(), &base, true)
                .unwrap()
                .rule_origins,
            warm.rule_origins
        );
    }

    #[test]
    fn missing_incomplete_invalid_and_old_cache_metadata_trigger_real_cold_reparse() {
        for case in [
            "missing",
            "partial",
            "extra",
            "absolute",
            "traversal",
            "old-format",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (lock, path, first_bytes) = install(dir.path());
            let base = dir.path().join("isolated-base");
            let key = cache::lock_sha256(&lock);
            let first = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
            assert_eq!(first.warmth, Warmth::Cold);
            if case == "old-format" {
                let file = cache::cache_file(dir.path(), &key);
                let mut bytes = fs::read(&file).unwrap();
                bytes[9..11].copy_from_slice(&1u16.to_be_bytes());
                fs::write(file, bytes).unwrap();
            } else {
                tamper(dir.path(), &key, |payload| match case {
                    "missing" => {
                        payload.as_object_mut().unwrap().remove("rule_origins");
                    }
                    "partial" => payload["rule_origins"] = serde_json::json!({}),
                    "extra" => {
                        payload["rule_origins"]["RULE-EXTRA"] =
                            payload["rule_origins"]["RULE-SAME"].clone()
                    }
                    "absolute" => {
                        payload["rule_origins"]["RULE-SAME"]["relative_path"] =
                            serde_json::json!(path)
                    }
                    "traversal" => {
                        payload["rule_origins"]["RULE-SAME"]["relative_path"] =
                            serde_json::json!("../rules/z-unrelated-winner.md")
                    }
                    _ => unreachable!(),
                });
            }
            let changed = first_bytes.replace("FIRST-SNAPSHOT", &format!("FRESH-{case}"));
            fs::write(&path, &changed).unwrap();
            let loaded = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
            let id = RuleId::parse("RULE-SAME").unwrap();
            assert_eq!(loaded.warmth, Warmth::Cold,
                "absent or invalid cached origins must reparse, never become a warm availability claim: {case}");
            assert_eq!(
                loaded.outcome.set.rules[&id].body.trim(),
                format!("FRESH-{case}")
            );
            assert_eq!(
                loaded.rule_origins.as_ref().unwrap()[&id].raw_sha256,
                cache::lock_sha256(changed.as_bytes())
            );
            assert_eq!(
                load_with_cache_and_rule_origins(dir.path(), &base, true)
                    .unwrap()
                    .warmth,
                Warmth::Warm
            );
        }
    }

    #[test]
    fn cache_write_refusal_preserves_cold_origins_and_missing_lock_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let (_lock, path, first_bytes) = install(dir.path());
        let base = dir.path().join("isolated-base");
        fs::write(dir.path().join(".cache"), "owned obstruction").unwrap();
        let loaded = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
        assert_eq!(loaded.warmth, Warmth::Cold);
        let id = RuleId::parse("RULE-SAME").unwrap();
        assert_eq!(
            loaded.rule_origins.as_ref().unwrap()[&id].raw_sha256,
            cache::lock_sha256(first_bytes.as_bytes())
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), first_bytes);
        fs::remove_file(dir.path().join(".coc/COC.lock")).unwrap();
        let fallback = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
        assert_eq!(fallback.warmth, Warmth::Cold);
        assert!(fallback.rule_origins.is_none());
        assert!(!matches!(
            fallback.outcome.set.source,
            CocSource::Coc { .. }
        ));
    }

    // Darwin/APFS rejects the invalid filename in fixture setup (EILSEQ).
    // This filesystem integration case remains exercised on other Unix targets;
    // the byte-path cache boundary below also executes on Darwin.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn non_utf8_selected_path_is_retained_when_cache_cannot_encode_it() {
        use std::os::unix::ffi::OsStringExt;
        #[cfg(not(target_os = "macos"))]
        {
            let dir = tempfile::tempdir().unwrap();
            build_coc_dir(dir.path(), b"{\"fixture\":\"nonutf8\"}");
            let filename = std::ffi::OsString::from_vec(b"actual-\xff-name.md".to_vec());
            let relative = PathBuf::from("rules").join(&filename);
            fs::write(
                dir.path().join(".coc").join(&relative),
                "---\nid: RULE-BYTES\n---\nBODY\n",
            )
            .unwrap();
            let base = dir.path().join("isolated-base");
            for _ in 0..2 {
                let loaded = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
                assert_eq!(loaded.warmth, Warmth::Cold);
                let id = RuleId::parse("RULE-BYTES").unwrap();
                assert_eq!(
                    loaded.rule_origins.as_ref().unwrap()[&id].relative_path,
                    relative
                );
                assert_eq!(loaded.outcome.set.rules[&id].body.trim(), "BODY");
            }
        }
        #[cfg(target_os = "macos")]
        {
            // APFS refuses invalid UTF-8 filenames. The public snapshot/cache
            // API still accepts an in-memory PathBuf, so exercise that boundary
            // without requiring a different mounted filesystem.
            let dir = tempfile::tempdir().unwrap();
            let lock = b"{\"fixture\":\"nonutf8\"}";
            build_coc_dir(dir.path(), lock);
            fs::write(
                dir.path().join(".coc/rules/actual-name.md"),
                "---\nid: RULE-BYTES\n---\nBODY\n",
            )
            .unwrap();
            let base = dir.path().join("isolated-base");
            let loaded = load_with_rule_origins(dir.path(), &base).unwrap();
            assert_eq!(loaded.warmth, Warmth::Cold);
            let id = RuleId::parse("RULE-BYTES").unwrap();
            let relative = PathBuf::from("rules").join(std::ffi::OsString::from_vec(
                b"actual-\xff-name.md".to_vec(),
            ));
            let mut parsed = parser::ParsedCocWithRuleOrigins {
                set: loaded.outcome.set,
                rule_origins: loaded.rule_origins.unwrap(),
            };
            parsed.rule_origins.get_mut(&id).unwrap().relative_path = relative;
            let key = cache::lock_sha256(lock);
            for _ in 0..2 {
                let error = cache::write_parsed_cache_with_rule_origins(dir.path(), &key, &parsed)
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                assert!(!cache::cache_file(dir.path(), &key).exists());
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn non_utf8_origin_cache_encoding_refuses_at_serializer_boundary() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let (lock, _, _) = install(dir.path());
        let base = dir.path().join("isolated-base");
        let selected = load_with_cache_and_rule_origins(dir.path(), &base, true).unwrap();
        let id = RuleId::parse("RULE-SAME").unwrap();
        assert_eq!(
            selected.outcome.set.rules[&id].body.trim(),
            "FIRST-SNAPSHOT"
        );
        let key = cache::lock_sha256(&lock);
        let cache_path = cache::cache_file(dir.path(), &key);
        let cache_before = fs::read(&cache_path).unwrap();
        let mut parsed = parser::ParsedCocWithRuleOrigins {
            set: selected.outcome.set.clone(),
            rule_origins: selected.rule_origins.clone().unwrap(),
        };
        assert_eq!(
            parsed.rule_origins[&id].relative_path,
            PathBuf::from("rules/z-unrelated-winner.md")
        );
        // Supply raw path bytes directly to the actual cache serializer; APFS
        // cannot create this name, so this is cache-boundary coverage there.
        parsed.rule_origins.get_mut(&id).unwrap().relative_path = PathBuf::from("rules").join(
            std::ffi::OsString::from_vec(b"actual-\xff-name.md".to_vec()),
        );
        let error =
            cache::write_parsed_cache_with_rule_origins(dir.path(), &key, &parsed).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::read(cache_path).unwrap(), cache_before);
        let cached = cache::read_parsed_cache_with_rule_origins(dir.path(), &key).unwrap();
        assert_eq!(cached.set, selected.outcome.set);
        assert_eq!(cached.rule_origins, selected.rule_origins.unwrap());
    }
}
