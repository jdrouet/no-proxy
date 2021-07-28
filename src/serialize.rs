use crate::NoProxy;
use serde::{de, Deserialize, Deserializer};
use serde::{ser::SerializeSeq, Serialize, Serializer};

impl Serialize for NoProxy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.content.len()))?;
        for elt in self.content.iter() {
            seq.serialize_element(&elt.to_string())?;
        }
        seq.end()
    }
}

struct NoProxyVisitor;

impl<'de> de::Visitor<'de> for NoProxyVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("string or list of strings")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value
            .split(',')
            .map(|item| item.trim().to_string())
            .collect())
    }

    fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
    where
        S: de::SeqAccess<'de>,
    {
        Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
    }
}

impl<'de> Deserialize<'de> for NoProxy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(NoProxyVisitor)
            .map(NoProxy::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serialize")]
    #[test]
    fn serialization() {
        let proxy = NoProxy::from("foo.bar,1.2.3.4");
        let json = serde_json::to_string(&proxy).unwrap();
        // parsing a comma separated string
        let result: NoProxy = serde_json::from_str(&json).unwrap();
        assert_eq!(proxy, result);
        assert_eq!(result.content.len(), 2);
        // parsing an array of strings
        let result: NoProxy = serde_json::from_str(r#"["foo.bar", "1.2.3.4"]"#).unwrap();
        assert_eq!(proxy, result);
        assert_eq!(result.content.len(), 2);
    }
}
