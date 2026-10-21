//! Canonical integer-only manifest encoding: RFC 8785 string/key rules and
//! exact safe integers. Lexical forms reaching safe integers are normalized.
use super::registry::RegistryError;
use serde_json::Value;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub fn canonical_content_bytes(value: &Value) -> Result<Vec<u8>, RegistryError> {
    let mut value = value.clone();
    value
        .as_object_mut()
        .ok_or(RegistryError::Malformed)?
        .remove("content_sha256");
    let mut bytes = Vec::new();
    encode(&value, &mut bytes)?;
    Ok(bytes)
}
fn encode(value: &Value, bytes: &mut Vec<u8>) -> Result<(), RegistryError> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            bytes.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                bytes.extend(serde_json::to_vec(key).map_err(|_| RegistryError::Malformed)?);
                bytes.push(b':');
                encode(&map[key], bytes)?;
            }
            bytes.push(b'}');
        }
        Value::Array(array) => {
            bytes.push(b'[');
            for (index, item) in array.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                encode(item, bytes)?;
            }
            bytes.push(b']');
        }
        Value::Number(number) => {
            let integer = if let Some(n) = number.as_i64() {
                if n.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(RegistryError::InvalidContract);
                }
                n.to_string()
            } else if let Some(n) = number.as_u64() {
                if n > MAX_SAFE_INTEGER {
                    return Err(RegistryError::InvalidContract);
                }
                n.to_string()
            } else if let Some(n) = number.as_f64() {
                if !n.is_finite() || n.fract() != 0.0 || n.abs() > MAX_SAFE_INTEGER as f64 {
                    return Err(RegistryError::InvalidContract);
                }
                (n as i64).to_string()
            } else {
                return Err(RegistryError::InvalidContract);
            };
            bytes.extend(integer.as_bytes());
        }
        _ => bytes.extend(serde_json::to_vec(value).map_err(|_| RegistryError::Malformed)?),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn frozen_1b_jcs_vectors_match_every_required_layer() {
        let bytes = include_bytes!("../../tests/fixtures/hook_registry_1b/jcs-vectors.json");
        assert_eq!(
            super::super::registry::sha256(bytes),
            "8ca358b69de77d002a2c47dc671ef90e7dfb9d69079d581839f46d29cc1a9894"
        );
        let vectors: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(vectors["vectors"].as_array().unwrap().len(), 15);
        for vector in vectors["vectors"].as_array().unwrap() {
            let parsed = super::super::registry::strict_json(
                vector["input_text"].as_str().unwrap().as_bytes(),
            );
            match vector["expect"].as_str().unwrap() {
                "canonical" => {
                    let mut out = vec![];
                    encode(&parsed.unwrap(), &mut out).unwrap();
                    assert_eq!(
                        out,
                        vector["canonical"].as_str().unwrap().as_bytes(),
                        "{}",
                        vector["name"]
                    );
                    assert_eq!(
                        super::super::registry::sha256(&out),
                        vector["sha256"].as_str().unwrap()
                    );
                }
                "refused-by-strict-parse" => assert!(parsed.is_err(), "{}", vector["name"]),
                other => panic!("unknown frozen vector expectation {other}"),
            }
        }
    }
    #[test]
    fn frozen_hook_registry_fixture_bytes_survive_autocrlf_checkout() {
        let _env_guard = crate::platform::test_env::lock();
        let repo = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let fixtures: [(&str, &[u8]); 5] = [
            (
                "csq-core/tests/fixtures/hook_registry_1b/schema.json",
                include_bytes!("../../tests/fixtures/hook_registry_1b/schema.json"),
            ),
            (
                "csq-core/tests/fixtures/hook_registry_1b/sample.json",
                include_bytes!("../../tests/fixtures/hook_registry_1b/sample.json"),
            ),
            (
                "csq-core/tests/fixtures/hook_registry_1b/jcs-vectors.json",
                include_bytes!("../../tests/fixtures/hook_registry_1b/jcs-vectors.json"),
            ),
            (
                "csq-core/tests/fixtures/hook-registry/hook-registry.schema.json",
                include_bytes!("../../tests/fixtures/hook-registry/hook-registry.schema.json"),
            ),
            (
                "csq-core/tests/fixtures/hook-registry/sample-trestle-base.manifest.json",
                include_bytes!(
                    "../../tests/fixtures/hook-registry/sample-trestle-base.manifest.json"
                ),
            ),
        ];
        std::fs::write(
            repo.path().join(".gitattributes"),
            include_bytes!("../../../.gitattributes"),
        )
        .unwrap();
        for (name, bytes) in fixtures {
            let path = repo.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::write(repo.path().join("control.json"), b"{}\n").unwrap();
        let git = |autocrlf: &str, args: &[&str]| {
            let output = crate::platform::test_git::command(repo.path(), home.path())
                .expect("sandbox Git command")
                .args(["-c", autocrlf, "-c", "core.attributesFile="])
                .args(args)
                .output()
                .expect("git must be available for the checkout regression");
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git("core.autocrlf=false", &["init", "--quiet"]);
        git("core.autocrlf=false", &["add", "."]);
        for (name, _) in fixtures {
            std::fs::remove_file(repo.path().join(name)).unwrap();
        }
        std::fs::remove_file(repo.path().join("control.json")).unwrap();
        git(
            "core.autocrlf=true",
            &["checkout-index", "--all", "--force"],
        );
        assert_eq!(
            std::fs::read(repo.path().join("control.json")).unwrap(),
            b"{}\r\n"
        );
        for (name, expected) in fixtures {
            let actual = std::fs::read(repo.path().join(name)).unwrap();
            assert_eq!(
                super::super::registry::sha256(&actual),
                super::super::registry::sha256(expected),
                "{name} changed during core.autocrlf=true checkout"
            );
        }
    }
    #[test]
    fn utf16_keys_escaping_and_safe_integer_vectors() {
        let v = json!({"\u{e000}":0,"\u{1f600}":1,"s":"\0\u{8}\t\n\u{c}\r\"\\/é\u{2028}","n":[-9007199254740991_i64,9007199254740991_u64,0,1000]});
        let expected = "{\"n\":[-9007199254740991,9007199254740991,0,1000],\"s\":\"\\u0000\\b\\t\\n\\f\\r\\\"\\\\/é\u{2028}\",\"😀\":1,\"\u{e000}\":0}";
        assert_eq!(canonical_content_bytes(&v).unwrap(), expected.as_bytes());
        for (raw, expected) in [("1e3", "1000"), ("1.0", "1"), ("-0", "0")] {
            let v: Value = serde_json::from_str(&format!("{{\"n\":{raw}}}")).unwrap();
            assert_eq!(
                canonical_content_bytes(&v).unwrap(),
                format!("{{\"n\":{expected}}}").as_bytes()
            );
        }
        for n in [
            json!(1.5),
            json!(9007199254740992_u64),
            json!(-9007199254740992_i64),
        ] {
            assert!(canonical_content_bytes(&json!({"n":n})).is_err());
        }
    }
}
