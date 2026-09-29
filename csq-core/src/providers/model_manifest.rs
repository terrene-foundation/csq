//! Reloadable model metadata and historical USD/1M-token prices.
//!
//! A manifest is a complete data snapshot, not executable/provider configuration.
//! Only a genuinely absent local file selects the bundled snapshot. Invalid local
//! data is an error, never permission to silently use different billing prices.
//! Callers load once per operation and retain that snapshot throughout the work.

use super::{ModelCatalog, ModelInfo};
use crate::usage::cost_rates::CostRate;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MAX_ROWS: usize = 4096;
const BUILTIN: &[u8] = include_bytes!("model-rates.builtin.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelManifest {
    pub schema_version: u32,
    pub revision: String,
    pub models: Vec<ModelInfo>,
    /// Ordered rules; the first matching rule owns the model even in an epoch
    /// gap. Legacy substring matching is explicit, not applied to new exact IDs.
    pub rates: Vec<RateRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateRule {
    pub match_kind: MatchKind,
    pub patterns: Vec<String>,
    pub strip_context_hint: bool,
    pub epochs: Vec<RateEpoch>,
    /// Human-readable evidence boundary; never fetched or executed.
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateEpoch {
    /// Inclusive UTC UNIX-second start; null means unbounded past.
    pub start_unix: Option<i64>,
    /// Exclusive UTC UNIX-second end; null means unbounded future.
    pub end_unix: Option<i64>,
    pub rate: RatePrices,
    pub peak: Option<PeakSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeakSchedule {
    /// ISO weekday numbers, Monday=1 through Sunday=7.
    pub weekdays: Vec<u8>,
    /// Sorted, disjoint half-open minute-of-day ranges in UTC. No implicit
    /// timezone, overnight wrapping, or holiday calendar.
    pub windows_utc: Vec<[u16; 2]>,
    pub rate: RatePrices,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RatePrices {
    pub input_per_1m_usd: f64,
    pub output_per_1m_usd: f64,
    pub cache_read_per_1m_usd: Option<f64>,
    pub cache_write_per_1m_usd: Option<f64>,
}

impl RatePrices {
    fn validate(&self) -> Result<()> {
        for value in [
            Some(self.input_per_1m_usd),
            Some(self.output_per_1m_usd),
            self.cache_read_per_1m_usd,
            self.cache_write_per_1m_usd,
        ]
        .into_iter()
        .flatten()
        {
            if !value.is_finite() || !(0.0..=1_000_000.0).contains(&value) {
                bail!("prices must be finite USD/1M values between 0 and 1000000");
            }
        }
        Ok(())
    }

    fn cost_rate(self) -> CostRate {
        CostRate {
            input_per_1m_usd: self.input_per_1m_usd,
            output_per_1m_usd: self.output_per_1m_usd,
            cache_read_per_1m_usd: self.cache_read_per_1m_usd,
            cache_write_per_1m_usd: self.cache_write_per_1m_usd,
        }
    }
}

fn bounded_text(value: &str, max: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} must be nonempty, bounded, trimmed text without control characters");
    }
    Ok(())
}

fn lookup_key(value: &str) -> String {
    value
        .split(['[', '@'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_lowercase()
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a raced-in symlink and do not block opening a FIFO. Validate
        // the opened descriptor, not a separate earlier path lookup.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point itself rather
        // than silently following its target; reject its attributes below.
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot open model manifest {}", path.display()))?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT, including symlinks and junctions.
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("model manifest must not be a reparse point");
        }
    }
    if !metadata.file_type().is_file() {
        bail!("model manifest must be a regular file, not a symlink or special file");
    }
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        bail!("model manifest exceeds {MAX_MANIFEST_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        bail!("model manifest exceeds {MAX_MANIFEST_BYTES} bytes");
    }
    Ok(bytes)
}

// Reject duplicate object keys before typed deserialization. serde_json's
// ordinary object/map handling accepts last-wins duplicates, which is unsafe
// for reviewed price/configuration files. Diagnostics deliberately omit the
// arbitrary offending key or value.
struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(
                self,
                value: f64,
            ) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| UniqueJson(n.into()))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(serde_json::Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = access.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(values.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    let UniqueJson(value) = access.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(values.into()))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

/// Validate a bounded, regular local file without installing it.
pub fn validate_file(path: &Path) -> Result<ModelManifest> {
    ModelManifest::from_slice(&read_bounded(path)?)
}

pub fn manifest_path(base_dir: &Path) -> PathBuf {
    base_dir.join("model-rates.json")
}

impl ModelManifest {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            bail!("model manifest exceeds {MAX_MANIFEST_BYTES} bytes");
        }
        let unique: UniqueJson = serde_json::from_slice(bytes).map_err(|error| {
            anyhow::anyhow!(
                "invalid manifest JSON (including duplicate keys) at line {}, column {}",
                error.line(),
                error.column()
            )
        })?;
        let manifest: Self = serde_json::from_value(unique.0)
            .map_err(|_| anyhow::anyhow!("invalid model manifest schema or fields"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Immutable bundled data is cached; local files are never process-cached.
    pub fn bundled() -> Self {
        static MANIFEST: OnceLock<ModelManifest> = OnceLock::new();
        MANIFEST
            .get_or_init(|| {
                Self::from_slice(BUILTIN).expect("bundled model manifest must validate")
            })
            .clone()
    }

    pub fn load(base_dir: &Path) -> Result<Self> {
        let path = manifest_path(base_dir);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::bundled()),
            Err(error) => Err(error).context("cannot inspect local model manifest"),
            Ok(_) => Self::from_slice(&read_bounded(&path)?)
                .with_context(|| format!("invalid local model manifest {}", path.display())),
        }
    }

    pub fn catalog(&self) -> ModelCatalog {
        ModelCatalog {
            models: self.models.clone(),
        }
    }

    /// Prices against the usage instant, never the wall clock. A dated or
    /// scheduled rule with no timestamp is unknown, including pre-epoch usage.
    pub fn rate_for_model_at(&self, model: &str, at: Option<DateTime<Utc>>) -> Option<CostRate> {
        let lower = model.to_lowercase();
        let rule = self.rates.iter().find(|rule| {
            let query = if rule.strip_context_hint {
                lower.strip_suffix("[1m]").unwrap_or(&lower)
            } else {
                &lower
            };
            rule.patterns.iter().any(|pattern| match rule.match_kind {
                MatchKind::Exact => query == pattern.to_lowercase(),
                MatchKind::Contains => query.contains(&pattern.to_lowercase()),
            })
        })?;
        if rule.epochs.len() == 1 {
            let epoch = &rule.epochs[0];
            if epoch.start_unix.is_none() && epoch.end_unix.is_none() && epoch.peak.is_none() {
                return Some(epoch.rate.cost_rate());
            }
        }
        let when = at?;
        let epoch = rule.epochs.iter().find(|epoch| {
            epoch
                .start_unix
                .is_none_or(|start| when.timestamp() >= start)
                && epoch.end_unix.is_none_or(|end| when.timestamp() < end)
        })?;
        if let Some(peak) = &epoch.peak {
            let minute = when.hour() * 60 + when.minute();
            if peak
                .weekdays
                .contains(&(when.weekday().number_from_monday() as u8))
                && peak
                    .windows_utc
                    .iter()
                    .any(|[start, end]| minute >= *start as u32 && minute < *end as u32)
            {
                return Some(peak.rate.cost_rate());
            }
        }
        Some(epoch.rate.cost_rate())
    }

    /// Validate before replacing any destination bytes. A same-directory
    /// create-new temporary file is synced then atomically renamed. No download,
    /// credential write, session migration or daemon restart is performed.
    pub fn install(base_dir: &Path, source: &Path) -> Result<Self> {
        let bytes = read_bounded(source)?;
        let manifest = Self::from_slice(&bytes)?;
        std::fs::create_dir_all(base_dir)?;
        let destination = manifest_path(base_dir);
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                bail!("manifest destination must be a regular file")
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let temporary = crate::platform::fs::unique_tmp_path(&destination);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // Only clean up after create_new succeeds: a collision is not ours.
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            crate::platform::fs::atomic_replace(&temporary, &destination)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported model manifest schema_version");
        }
        bounded_text(&self.revision, 128, "revision")?;
        if self.models.is_empty()
            || self.models.len() > MAX_ROWS
            || self.rates.is_empty()
            || self.rates.len() > MAX_ROWS
        {
            bail!("models and rates must each contain 1..={MAX_ROWS} rows");
        }
        let mut model_keys: HashMap<String, usize> = HashMap::new();
        for (index, model) in self.models.iter().enumerate() {
            bounded_text(&model.id, 256, "model id")?;
            bounded_text(&model.name, 256, "model name")?;
            if super::registry::lookup(&model.provider).is_none() {
                bail!("unknown model provider");
            }
            if model.context_window == Some(0) || model.output_limit == Some(0) {
                bail!("model token limits must be positive when known");
            }
            if model.aliases.len() > 128 {
                bail!("too many model aliases");
            }
            for value in std::iter::once(&model.id).chain(&model.aliases) {
                bounded_text(value, 256, "model id or alias")?;
                let key = lookup_key(value);
                if key.is_empty() {
                    bail!("empty normalized model id or alias");
                }
                if model_keys
                    .insert(key, index)
                    .is_some_and(|other| other != index)
                {
                    bail!("ambiguous normalized model id or alias");
                }
            }
        }
        let mut pattern_keys = HashMap::new();
        for (index, rule) in self.rates.iter().enumerate() {
            bounded_text(&rule.evidence, 4096, "rate evidence")?;
            if rule.patterns.is_empty()
                || rule.patterns.len() > 128
                || rule.epochs.is_empty()
                || rule.epochs.len() > 128
            {
                bail!("rate patterns and epochs must contain 1..=128 rows");
            }
            for pattern in &rule.patterns {
                bounded_text(pattern, 256, "rate pattern")?;
                // Exact and contains duplicates are rejected independently;
                // explicitly ordered, overlapping legacy patterns are allowed.
                let key = (
                    matches!(rule.match_kind, MatchKind::Contains),
                    pattern.to_lowercase(),
                );
                if pattern_keys.insert(key, index).is_some() {
                    bail!("duplicate rate pattern");
                }
            }
            let mut previous_end = None;
            for (epoch_index, epoch) in rule.epochs.iter().enumerate() {
                if epoch
                    .start_unix
                    .zip(epoch.end_unix)
                    .is_some_and(|(start, end)| start >= end)
                {
                    bail!("rate epoch must have start before end");
                }
                if epoch_index > 0
                    && (previous_end.is_none()
                        || epoch.start_unix.is_none()
                        || epoch.start_unix < previous_end)
                {
                    bail!("rate epochs must be ordered and disjoint");
                }
                for time in [epoch.start_unix, epoch.end_unix].into_iter().flatten() {
                    if DateTime::<Utc>::from_timestamp(time, 0).is_none() {
                        bail!("rate epoch timestamp outside supported UTC range");
                    }
                }
                previous_end = epoch.end_unix;
                epoch.rate.validate()?;
                if let Some(peak) = &epoch.peak {
                    peak.rate.validate()?;
                    if peak.weekdays.is_empty() || peak.weekdays.len() > 7 {
                        bail!("peak weekdays must contain 1..=7 unique ISO weekdays");
                    }
                    let mut days = [false; 7];
                    for day in &peak.weekdays {
                        if !(1..=7).contains(day) || days[(*day - 1) as usize] {
                            bail!("peak weekday invalid or duplicated");
                        }
                        days[(*day - 1) as usize] = true;
                    }
                    if peak.windows_utc.is_empty() || peak.windows_utc.len() > 1440 {
                        bail!("peak windows must contain 1..=1440 disjoint windows");
                    }
                    let mut last_end = 0;
                    for [start, end] in &peak.windows_utc {
                        if start >= end || *end > 1440 || *start < last_end {
                            bail!("peak windows must be ordered disjoint UTC minutes in [0,1440]");
                        }
                        last_end = *end;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Explicitly restore bundled defaults for future readers. No other files are
/// removed and a missing local manifest is already the desired state.
pub fn reset(base_dir: &Path) -> Result<bool> {
    match std::fs::remove_file(manifest_path(base_dir)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use tempfile::TempDir;

    fn fixture() -> Value {
        serde_json::to_value(ModelManifest::bundled()).unwrap()
    }

    fn parse(value: &Value) -> Result<ModelManifest> {
        ModelManifest::from_slice(&serde_json::to_vec(value).unwrap())
    }

    fn instant(value: &str) -> Option<DateTime<Utc>> {
        Some(
            DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&Utc),
        )
    }

    #[test]
    fn bundled_manifest_has_all_extracted_models_and_rate_rules() {
        let manifest = ModelManifest::from_slice(BUILTIN).unwrap();
        assert_eq!(manifest.models.len(), 14);
        assert_eq!(manifest.rates.len(), 31);
        assert_eq!(manifest.catalog().find("4.1").unwrap().id, "deepseek-flash");
        assert_eq!(
            manifest.catalog().find("opus").unwrap().context_window,
            Some(1_000_000)
        );
        assert!(manifest.rate_for_model_at("deepseek-flash", None).is_none());
        assert!(manifest
            .rate_for_model_at("totally-unrecognized-model", None)
            .is_none());
    }

    #[test]
    fn malformed_truncated_and_duplicate_json_keys_are_rejected() {
        for bytes in [
            b"{".as_slice(),
            b"null",
            b"[]",
            br#"{"schema_version":1,"schema_version":1}"#,
            br#"{"nested":{"price":1,"price":2}}"#,
        ] {
            assert!(ModelManifest::from_slice(bytes).is_err());
        }
    }

    #[test]
    fn complete_manifest_duplicate_root_and_price_keys_are_rejected() {
        let original = std::str::from_utf8(BUILTIN).unwrap();
        assert!(ModelManifest::from_slice(original.as_bytes()).is_ok());
        for (needle, replacement) in [
            (
                "\"schema_version\": 1",
                "\"schema_version\": 1, \"schema_version\": 1",
            ),
            (
                "\"input_per_1m_usd\": 0.15",
                "\"input_per_1m_usd\": 0.15, \"input_per_1m_usd\": 0.15",
            ),
        ] {
            assert!(original.contains(needle));
            let duplicate = original.replacen(needle, replacement, 1);
            assert_ne!(duplicate, original);
            // Ordinary JSON map parsing loses duplicates before typed schema
            // validation. Show the remaining content is otherwise valid.
            let ordinary_json: Value = serde_json::from_str(&duplicate).unwrap();
            let ordinary: ModelManifest = serde_json::from_value(ordinary_json).unwrap();
            ordinary.validate().unwrap();
            assert!(ModelManifest::from_slice(duplicate.as_bytes()).is_err());
        }
    }

    #[test]
    fn unknown_fields_and_versions_fail_without_echoing_arbitrary_data() {
        for location in ["root", "model", "rule", "epoch", "price", "peak"] {
            let mut value = fixture();
            let object = match location {
                "root" => &mut value,
                "model" => &mut value["models"][0],
                "rule" => &mut value["rates"][0],
                "epoch" => &mut value["rates"][0]["epochs"][0],
                "price" => &mut value["rates"][0]["epochs"][0]["rate"],
                _ => &mut value["rates"][0]["epochs"][0]["peak"],
            };
            object["PRIVATE_SENTINEL"] = json!("not-a-real-secret");
            let error = parse(&value).unwrap_err().to_string();
            assert!(!error.contains("PRIVATE_SENTINEL"));
            assert!(!error.contains("not-a-real-secret"));
        }
        let mut value = fixture();
        value["schema_version"] = json!(2);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn duplicate_normalized_models_and_aliases_are_rejected() {
        let mut value = fixture();
        value["models"][1]["aliases"]
            .as_array_mut()
            .unwrap()
            .push(json!("CLAUDE-OPUS-4-8[1m]@default"));
        assert!(parse(&value).is_err());
        let mut value = fixture();
        value["models"][0]["aliases"]
            .as_array_mut()
            .unwrap()
            .push(json!("CLAUDE-OPUS-4-8[1m]"));
        assert!(
            parse(&value).is_ok(),
            "same-row canonical aliases are not ambiguous"
        );
        let mut value = fixture();
        value["models"][1]["id"] = value["models"][0]["id"].clone();
        assert!(parse(&value).is_err());
    }

    #[test]
    fn unknown_providers_empty_keys_and_zero_limits_are_rejected() {
        for (field, replacement) in [
            ("provider", json!("unregistered-provider")),
            ("id", json!("")),
            ("context_window", json!(0)),
            ("output_limit", json!(0)),
            ("name", json!("bad\nname")),
        ] {
            let mut value = fixture();
            value["models"][0][field] = replacement;
            assert!(parse(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn negative_nonfinite_and_unbounded_prices_are_rejected() {
        let mut value = fixture();
        value["rates"][0]["epochs"][0]["rate"]["input_per_1m_usd"] = json!(-1.0);
        assert!(parse(&value).is_err());
        let mut manifest = ModelManifest::bundled();
        manifest.rates[0].epochs[0].rate.output_per_1m_usd = f64::INFINITY;
        assert!(manifest.validate().is_err());
        manifest.rates[0].epochs[0].rate.output_per_1m_usd = 1_000_001.0;
        assert!(manifest.validate().is_err());
        manifest.rates[0].epochs[0].rate.output_per_1m_usd = 0.0;
        manifest.rates[0].epochs[0].rate.cache_read_per_1m_usd = Some(-0.01);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn invalid_overlapping_and_unordered_epochs_are_rejected() {
        for (start, end) in [
            (json!(10), json!(10)),
            (json!(11), json!(10)),
            (json!(i64::MAX), Value::Null),
        ] {
            let mut value = fixture();
            value["rates"][0]["epochs"][0]["start_unix"] = start;
            value["rates"][0]["epochs"][0]["end_unix"] = end;
            assert!(parse(&value).is_err());
        }
        let mut value = fixture();
        value["rates"][1]["epochs"][1]["start_unix"] = json!(1);
        assert!(parse(&value).is_err());
        let mut value = fixture();
        value["rates"][1]["epochs"][0]["end_unix"] = Value::Null;
        assert!(parse(&value).is_err());
    }

    #[test]
    fn invalid_weekdays_and_peak_windows_are_rejected() {
        for days in [json!([]), json!([0]), json!([8]), json!([1, 1])] {
            let mut value = fixture();
            value["rates"][0]["epochs"][0]["peak"]["weekdays"] = days;
            assert!(parse(&value).is_err());
        }
        for windows in [
            json!([]),
            json!([[60, 60]]),
            json!([[100, 90]]),
            json!([[0, 1441]]),
            json!([[60, 240], [200, 300]]),
            json!([[300, 400], [0, 100]]),
        ] {
            let mut value = fixture();
            value["rates"][0]["epochs"][0]["peak"]["windows_utc"] = windows;
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn duplicated_rate_patterns_are_rejected_but_ordered_legacy_contains_survives() {
        let mut value = fixture();
        let duplicate = value["rates"][0].clone();
        value["rates"].as_array_mut().unwrap().push(duplicate);
        assert!(parse(&value).is_err());
        assert_eq!(
            ModelManifest::bundled()
                .rate_for_model_at("glm-5.3[1m]", None)
                .unwrap()
                .input_per_1m_usd,
            1.4
        );
        assert_eq!(
            ModelManifest::bundled()
                .rate_for_model_at("glm-unverified-legacy-fallback", None)
                .unwrap()
                .input_per_1m_usd,
            0.6
        );
    }

    #[test]
    fn epoch_gaps_and_missing_time_never_fall_through_to_later_rules() {
        let mut manifest = ModelManifest::bundled();
        let mut fallback = manifest.rates[3].clone();
        fallback.match_kind = MatchKind::Contains;
        fallback.patterns = vec!["deepseek-flash".into()];
        manifest.rates.push(fallback);
        manifest.validate().unwrap();
        assert!(manifest.rate_for_model_at("deepseek-flash", None).is_none());
        assert!(manifest
            .rate_for_model_at("deepseek-flash", instant("2026-09-10T03:59:59Z"))
            .is_none());
        assert_eq!(
            manifest
                .rate_for_model_at("deepseek-flash", instant("2026-09-10T04:00:00Z"))
                .unwrap()
                .input_per_1m_usd,
            0.15
        );
    }

    #[test]
    fn minute_windows_use_half_open_utc_boundaries_and_iso_weekdays() {
        let mut manifest = ModelManifest::bundled();
        manifest.rates[0].epochs[0]
            .peak
            .as_mut()
            .unwrap()
            .windows_utc = vec![[90, 91]];
        manifest.validate().unwrap();
        for (time, input) in [
            ("2026-09-14T01:29:59Z", 0.15),
            ("2026-09-14T01:30:00Z", 0.30),
            ("2026-09-14T01:30:59Z", 0.30),
            ("2026-09-14T01:31:00Z", 0.15),
            ("2026-09-13T01:30:00Z", 0.15),
        ] {
            assert_eq!(
                manifest
                    .rate_for_model_at("deepseek-flash", instant(time))
                    .unwrap()
                    .input_per_1m_usd,
                input,
                "{time}"
            );
        }
    }

    #[test]
    fn missing_manifest_falls_back_but_present_invalid_manifest_fails() {
        let dir = TempDir::new().unwrap();
        assert_eq!(
            ModelManifest::load(dir.path()).unwrap().revision,
            "2026-09-29.builtin"
        );
        std::fs::write(manifest_path(dir.path()), b"{").unwrap();
        assert!(ModelManifest::load(dir.path()).is_err());
        std::fs::remove_file(manifest_path(dir.path())).unwrap();
        std::fs::create_dir(manifest_path(dir.path())).unwrap();
        assert!(ModelManifest::load(dir.path()).is_err());
    }

    #[test]
    fn oversized_file_and_in_memory_manifest_are_rejected_before_parse() {
        let dir = TempDir::new().unwrap();
        let bytes = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(ModelManifest::from_slice(&bytes).is_err());
        std::fs::write(manifest_path(dir.path()), bytes).unwrap();
        assert!(ModelManifest::load(dir.path()).is_err());
    }

    #[test]
    fn invalid_install_preserves_exact_destination_bytes_and_leaves_no_tempfile() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("source.json");
        std::fs::write(&source, BUILTIN).unwrap();
        ModelManifest::install(dir.path(), &source).unwrap();
        let before = std::fs::read(manifest_path(dir.path())).unwrap();
        std::fs::write(&source, b"{ truncated").unwrap();
        assert!(ModelManifest::install(dir.path(), &source).is_err());
        assert_eq!(std::fs::read(manifest_path(dir.path())).unwrap(), before);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn atomic_install_hot_reloads_new_model_and_cost_without_process_restart() {
        let dir = TempDir::new().unwrap();
        let before = ModelManifest::load(dir.path()).unwrap();
        assert!(before.catalog().find("private-test-model").is_none());
        let mut value = fixture();
        value["revision"] = json!("private-update-1");
        value["models"].as_array_mut().unwrap().push(json!({"id":"private-test-model","name":"Private fixture","provider":"deepseek","context_window":2_000_000,"output_limit":1000,"aliases":["fixture-alias"]}));
        let mut rule = value["rates"][3].clone();
        rule["match_kind"] = json!("exact");
        rule["patterns"] = json!(["private-test-model"]);
        rule["evidence"] = json!("Synthetic private fixture; not vendor pricing");
        rule["epochs"][0]["rate"]["input_per_1m_usd"] = json!(7.0);
        value["rates"].as_array_mut().unwrap().push(rule);
        let source = dir.path().join("source.json");
        std::fs::write(&source, serde_json::to_vec(&value).unwrap()).unwrap();
        ModelManifest::install(dir.path(), &source).unwrap();
        let after = ModelManifest::load(dir.path()).unwrap();
        assert_eq!(after.revision, "private-update-1");
        assert_eq!(
            after
                .catalog()
                .find("fixture-alias")
                .unwrap()
                .context_window,
            Some(2_000_000)
        );
        assert_eq!(
            after
                .rate_for_model_at("private-test-model", None)
                .unwrap()
                .input_per_1m_usd,
            7.0
        );
        assert!(
            before
                .rate_for_model_at("private-test-model", None)
                .is_none(),
            "previous snapshots remain immutable"
        );
        assert!(reset(dir.path()).unwrap());
        assert!(!reset(dir.path()).unwrap());
        assert!(ModelManifest::load(dir.path())
            .unwrap()
            .catalog()
            .find("private-test-model")
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_manifest_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new().unwrap();
        let path = manifest_path(dir.path());
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Private fixture only. Opening this FIFO without O_NONBLOCK would
        // wait indefinitely: no writer is created by this test.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(ModelManifest::load(dir.path()).is_err());
        assert!(validate_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_manifest_and_install_destination_are_rejected() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("source.json");
        std::fs::write(&source, BUILTIN).unwrap();
        std::os::unix::fs::symlink(&source, manifest_path(dir.path())).unwrap();
        assert!(ModelManifest::load(dir.path()).is_err());
        assert!(ModelManifest::install(dir.path(), &source).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), BUILTIN);
    }
}
