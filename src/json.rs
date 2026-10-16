//! Strict JSON input: duplicate members must never silently replace a declaration.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object members")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Number::from_f64(v)
                    .map(|v| Unique(Value::Number(v)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut items = Vec::new();
                while let Some(Unique(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Unique(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut items = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if items.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON member: {key}")));
                    }
                    let Unique(value) = map.next_value()?;
                    items.insert(key, value);
                }
                Ok(Unique(Value::Object(items)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_value(parse_value(bytes)?).map_err(|e| e.to_string())
}

/// Return the strictly parsed value without reconstructing an already validated JSON tree.
pub(crate) fn parse_value(bytes: &[u8]) -> Result<Value, String> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let Unique(value) = Unique::deserialize(&mut parser).map_err(|e| e.to_string())?;
    parser.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// Borrow a declared output object without creating members on a non-object value.
pub(crate) fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| "JSON output record is not an object".into())
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_value};
    use serde::Deserialize;
    use serde_json::{Value, json};

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        payload: Value,
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check exact JSON content and typed decoding equivalence"
    )]
    fn strict_value_and_typed_parsing_preserve_nested_content() -> Result<(), String> {
        let bytes = br#"{"payload":{"items":[null,true,-2,1.25,{"text":"a\u0062"}]}}"#;
        let direct = parse_value(bytes)?;
        let typed: Envelope = parse(bytes)?;
        assert_eq!(
            direct,
            json!({"payload":{"items":[null,true,-2,1.25,{"text":"ab"}]}})
        );
        assert_eq!(parse::<Value>(bytes)?, direct);
        assert_eq!(direct.get("payload"), Some(&typed.payload));
        Ok(())
    }

    #[test]
    fn strict_value_and_typed_parsing_refuse_the_same_invalid_json() {
        let invalid: &[&[u8]] = &[
            br#"{"payload":1,"payload":2}"#,
            br#"{"payload":{"same":1,"sa\u006de":2}}"#,
            br#"{"payload":[{"same":1,"same":2}]}"#,
            br#"{"payload":1} {"payload":2}"#,
            br#"{"payload":1} trailing"#,
            br#"{"payload":[true,]}"#,
        ];
        for bytes in invalid {
            let direct = parse_value(bytes);
            let typed = parse::<Envelope>(bytes);
            assert!(direct.is_err());
            assert_eq!(direct.err(), typed.err());
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions preserve typed shape and unknown-field refusals after strict value parsing"
    )]
    fn typed_contracts_remain_required_after_value_validation() -> Result<(), String> {
        for bytes in [br#"[1,2]"#.as_slice(), br#"{"other":1}"#.as_slice()] {
            parse_value(bytes)?;
            assert!(parse::<Envelope>(bytes).is_err());
        }
        Ok(())
    }
}
