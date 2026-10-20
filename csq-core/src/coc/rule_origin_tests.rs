// Local parsed-rule provenance regression fixtures; no producer-schema claim.
mod rule_origin_tests {
    use super::*;
    use std::cell::Cell;

    fn rule_text(id: &str, precedence: i32, body: &str) -> String {
        format!("---\nid: {id}\npaths: [src/**]\nprecedence: {precedence}\n---\n{body}\n")
    }

    #[test]
    fn winning_origin_follows_precedence_in_both_filename_orders() {
        for winner_first in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            build_minimal_coc(dir.path());
            let (winner_name, loser_name) = if winner_first {
                ("a-unrelated-name.md", "z-other-name.md")
            } else {
                ("z-unrelated-name.md", "a-other-name.md")
            };
            let winner = rule_text("RULE-SAME", 9, "WINNING-BODY");
            let loser = rule_text("RULE-SAME", 1, "LOSING-BODY");
            let other = rule_text("RULE-OTHER", 0, "OTHER-BODY");
            write_md(&dir.path().join("rules"), winner_name, &winner);
            write_md(&dir.path().join("rules"), loser_name, &loser);
            write_md(&dir.path().join("rules"), "middle-name.md", &other);
            // Non-rule kinds retain their original reader and CocSet projection.
            for (kind, id) in [
                ("agents", "AGENT-X"),
                ("skills", "SKILL-X"),
                ("commands", "CMD-X"),
            ] {
                write_md(
                    &dir.path().join(kind),
                    "unrelated.md",
                    &format!("---\nid: {id}\n---\n{kind} body\n"),
                );
            }
            let parsed =
                parse_coc_dir_with_rule_origins(dir.path(), CocSource::LegacyClaude).unwrap();
            let id = RuleId::parse("RULE-SAME").unwrap();
            assert_eq!(parsed.set.rules[&id].body.trim(), "WINNING-BODY");
            assert_eq!(parsed.set.rules[&id].precedence, 9);
            assert_eq!(
                parsed.rule_origins[&id].relative_path,
                PathBuf::from("rules").join(winner_name),
                "winning origin must replace the losing path atomically"
            );
            assert_eq!(
                parsed.rule_origins[&id].raw_sha256,
                <[u8; 32]>::from(Sha256::digest(winner.as_bytes())),
                "winning origin must replace the losing raw hash atomically"
            );
            let other_id = RuleId::parse("RULE-OTHER").unwrap();
            assert_eq!(
                parsed.rule_origins[&other_id].relative_path,
                PathBuf::from("rules/middle-name.md")
            );
            assert_eq!(
                parsed.rule_origins[&other_id].raw_sha256,
                <[u8; 32]>::from(Sha256::digest(other.as_bytes()))
            );
            assert_eq!(
                parsed.rule_origins.keys().collect::<Vec<_>>(),
                parsed.set.rules.keys().collect::<Vec<_>>()
            );
            assert_eq!(
                parsed.set,
                parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap()
            );
            assert_eq!(
                (
                    parsed.set.agents.len(),
                    parsed.set.skills.len(),
                    parsed.set.commands.len()
                ),
                (1, 1, 1)
            );
        }
    }

    #[test]
    fn raw_hash_and_body_use_same_first_read_during_file_change() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        let path = dir.path().join("rules/not-the-id.md");
        let first = rule_text("RULE-RACE", 4, "FIRST-SNAPSHOT");
        let second = rule_text("RULE-RACE", 4, "REPLACED-ON-DISK");
        fs::write(&path, &first).unwrap();
        let reads = Cell::new(0);
        let reader = |selected: &Path| {
            assert_eq!(selected, path);
            reads.set(reads.get() + 1);
            let captured = fs::read_to_string(selected)?;
            fs::write(selected, &second)?;
            Ok(captured)
        };
        let parsed =
            parse_coc_dir_with_rule_origins_using(dir.path(), CocSource::LegacyClaude, &reader)
                .unwrap();
        let id = RuleId::parse("RULE-RACE").unwrap();
        assert_eq!(parsed.set.rules[&id].body.trim(), "FIRST-SNAPSHOT");
        assert_eq!(fs::read_to_string(&path).unwrap(), second);
        assert_eq!(
            reads.get(),
            1,
            "one read supplies each rule definition and origin"
        );
        assert_eq!(
            parsed.rule_origins[&id].raw_sha256,
            <[u8; 32]>::from(Sha256::digest(first.as_bytes())),
            "raw origin hash must describe the parsed snapshot, not a later file read"
        );
        assert_ne!(
            parsed.rule_origins[&id].raw_sha256,
            <[u8; 32]>::from(Sha256::digest(second.as_bytes()))
        );
        assert_eq!(
            parsed.rule_origins[&id].relative_path,
            PathBuf::from("rules/not-the-id.md")
        );
    }

    #[test]
    fn origins_api_preserves_equal_precedence_duplicate_paths() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        let a = dir.path().join("rules/a-name.md");
        let b = dir.path().join("rules/b-name.md");
        fs::write(&a, rule_text("RULE-SAME", 5, "FIRST")).unwrap();
        fs::write(&b, rule_text("RULE-SAME", 5, "SECOND")).unwrap();
        for err in [
            parse_coc_dir_with_rule_origins(dir.path(), CocSource::LegacyClaude).unwrap_err(),
            parse_coc_dir(dir.path(), CocSource::LegacyClaude).unwrap_err(),
        ] {
            match err {
                ParseError::DuplicateId {
                    id,
                    a: actual_a,
                    b: actual_b,
                } => {
                    assert_eq!(id, "RULE-SAME");
                    assert_eq!(actual_a, a);
                    assert_eq!(actual_b, b);
                }
                other => panic!("duplicate authority changed: {other:?}"),
            }
        }
    }

    #[test]
    fn origin_reader_error_retains_original_io_kind_and_path() {
        let dir = tempfile::tempdir().unwrap();
        build_minimal_coc(dir.path());
        let path = dir.path().join("rules/reader-error.md");
        fs::write(&path, rule_text("RULE-ERROR", 0, "BODY")).unwrap();
        let reader = |_: &Path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture read refusal",
            ))
        };
        match parse_coc_dir_with_rule_origins_using(dir.path(), CocSource::LegacyClaude, &reader)
            .unwrap_err()
        {
            ParseError::Io {
                path: actual,
                source,
            } => {
                assert_eq!(actual, path);
                assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(source.to_string(), "fixture read refusal");
            }
            other => panic!("rule read error changed: {other:?}"),
        }
    }
}
