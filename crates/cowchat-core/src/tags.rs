//! Message tags: structured labels stored at `metadata.tags`.
//!
//! The server sets each tag's `source`, so readers can tell a label the author
//! chose from one the server extracted. Filters use the spec form: `key` matches
//! any value and `key=value` matches exactly.

use serde::{Deserialize, Serialize};

pub const MAX_TAGS_PER_MESSAGE: usize = 32;
pub const MAX_TAG_KEY_BYTES: usize = 64;
pub const MAX_TAG_VALUE_BYTES: usize = 128;
pub const TAG_SOURCE_AUTHOR: &str = "author";
pub const TAG_SOURCE_EXTRACTOR: &str = "extractor";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageTag {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl MessageTag {
    /// Parse a `key` or `key=value` spec.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (key, value) = match spec.split_once('=') {
            Some((key, value)) => (key, Some(value.to_owned())),
            None => (spec, None),
        };
        let tag = Self {
            key: key.to_owned(),
            value,
            source: None,
        };
        tag.validate()?;
        Ok(tag)
    }

    pub fn validate(&self) -> Result<(), String> {
        let key_is_valid = !self.key.is_empty()
            && self.key.len() <= MAX_TAG_KEY_BYTES
            && self
                .key
                .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && self.key.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            });
        if !key_is_valid {
            return Err(format!(
                "tag key must be 1..{MAX_TAG_KEY_BYTES} bytes of a-z, 0-9, '.', '_' or '-', starting with a letter or digit"
            ));
        }
        if let Some(value) = &self.value {
            if value.is_empty()
                || value.len() > MAX_TAG_VALUE_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(format!(
                    "tag value must be 1..{MAX_TAG_VALUE_BYTES} bytes without control characters"
                ));
            }
        }
        Ok(())
    }

    fn matches(&self, filter: &MessageTag) -> bool {
        self.key == filter.key && (filter.value.is_none() || self.value == filter.value)
    }
}

/// The tags on a message. Metadata that does not hold a tag list has none.
pub fn metadata_tags(metadata: &serde_json::Value) -> Vec<MessageTag> {
    metadata
        .get("tags")
        .and_then(|tags| serde_json::from_value(tags.clone()).ok())
        .unwrap_or_default()
}

/// True when no filters are set or the message carries any filtered tag.
pub fn tags_match_any(filters: &[String], metadata: &serde_json::Value) -> bool {
    if filters.is_empty() {
        return true;
    }
    let tags = metadata_tags(metadata);
    filters
        .iter()
        .filter_map(|filter| MessageTag::parse(filter).ok())
        .any(|filter| tags.iter().any(|tag| tag.matches(&filter)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_splits_on_the_first_equals_sign() {
        let tag = MessageTag::parse("topic=a=b").unwrap();
        assert_eq!(tag.key, "topic");
        assert_eq!(tag.value.as_deref(), Some("a=b"));
        assert_eq!(MessageTag::parse("urgent").unwrap().value, None);
    }

    #[test]
    fn parse_rejects_malformed_specs() {
        for spec in [
            "",
            "=value",
            "topic=",
            "Topic",
            "-topic",
            "to pic",
            "topic=a\nb",
        ] {
            assert!(MessageTag::parse(spec).is_err(), "{spec:?}");
        }
        assert!(MessageTag::parse(&"k".repeat(MAX_TAG_KEY_BYTES + 1)).is_err());
        assert!(MessageTag::parse(&format!("k={}", "v".repeat(MAX_TAG_VALUE_BYTES + 1))).is_err());
        assert!(MessageTag::parse(&"k".repeat(MAX_TAG_KEY_BYTES)).is_ok());
    }

    #[test]
    fn a_key_filter_matches_any_value_and_a_pair_matches_exactly() {
        let metadata = json!({"tags":[{"key":"topic","value":"router","source":"author"}]});
        let matches = |filter: &str| tags_match_any(&[filter.to_owned()], &metadata);
        assert!(matches("topic"));
        assert!(matches("topic=router"));
        assert!(!matches("topic=views"));
        assert!(!matches("other"));
    }

    #[test]
    fn a_pair_filter_does_not_match_a_tag_without_a_value() {
        let metadata = json!({"tags":[{"key":"urgent"}]});
        assert!(tags_match_any(&["urgent".to_owned()], &metadata));
        assert!(!tags_match_any(&["urgent=yes".to_owned()], &metadata));
    }

    #[test]
    fn filters_are_any_of_and_empty_filters_match_everything() {
        let metadata = json!({"tags":[{"key":"b"}]});
        assert!(tags_match_any(&["a".to_owned(), "b".to_owned()], &metadata));
        assert!(tags_match_any(&[], &json!({})));
        assert!(!tags_match_any(&["a".to_owned()], &json!({})));
    }

    #[test]
    fn malformed_stored_tags_read_as_no_tags() {
        assert!(metadata_tags(&json!({"tags":"topic"})).is_empty());
        assert!(!tags_match_any(
            &["topic".to_owned()],
            &json!({"tags":["topic"]})
        ));
    }
}
