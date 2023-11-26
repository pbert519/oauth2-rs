use alloc::{string::{String, ToString}, vec::Vec};
use serde::{Deserialize, Deserializer, Serializer};

///
/// Serde case-insensitive deserializer for an untagged `enum`.
///
/// This function converts values to lowercase before deserializing as the `enum`. Requires the
/// `#[serde(rename_all = "lowercase")]` attribute to be set on the `enum`.
///
/// # Example
///
/// In example below, the following JSON values all deserialize to
/// `GroceryBasket { fruit_item: Fruit::Banana }`:
///
///  * `{"fruit_item": "banana"}`
///  * `{"fruit_item": "BANANA"}`
///  * `{"fruit_item": "Banana"}`
///
/// Note: this example does not compile automatically due to
/// [Rust issue #29286](https://github.com/rust-lang/rust/issues/29286).
///
/// ```
/// # /*
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// #[serde(rename_all = "lowercase")]
/// enum Fruit {
///     Apple,
///     Banana,
///     Orange,
/// }
///
/// #[derive(Deserialize)]
/// struct GroceryBasket {
///     #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
///     fruit_item: Fruit,
/// }
/// # */
/// ```
///
pub fn deserialize_untagged_enum_case_insensitive<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;
    T::deserialize(Value::String(
        String::deserialize(deserializer)?.to_lowercase(),
    ))
    .map_err(Error::custom)
}

///
/// Serde space-delimited string deserializer for a `Vec<String>`.
///
/// This function splits a JSON string at each space character into a `Vec<String>` .
///
/// # Example
///
/// In example below, the JSON value `{"items": "foo bar baz"}` would deserialize to:
///
/// ```
/// # struct GroceryBasket {
/// #     items: Vec<String>,
/// # }
/// GroceryBasket {
///     items: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
/// };
/// ```
///
/// Note: this example does not compile automatically due to
/// [Rust issue #29286](https://github.com/rust-lang/rust/issues/29286).
///
/// ```
/// # /*
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct GroceryBasket {
///     #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
///     items: Vec<String>,
/// }
/// # */
/// ```
///
pub fn deserialize_space_delimited_vec<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;
    if let Some(space_delimited) = Option::<String>::deserialize(deserializer)? {
        let entries = space_delimited
            .split(' ')
            .map(|s| Value::String(s.to_string()))
            .collect();
        T::deserialize(Value::Array(entries)).map_err(Error::custom)
    } else {
        // If the JSON value is null, use the default value.
        Ok(T::default())
    }
}

///
/// Serde space-delimited string serializer for an `Option<Vec<String>>`.
///
/// This function serializes a string vector into a single space-delimited string.
/// If `string_vec_opt` is `None`, the function serializes it as `None` (e.g., `null`
/// in the case of JSON serialization).
///
pub fn serialize_space_delimited_vec<T, S>(
    vec_opt: &Option<Vec<T>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: AsRef<str>,
    S: Serializer,
{
    if let Some(ref vec) = *vec_opt {
        let space_delimited = vec.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(" ");

        serializer.serialize_str(&space_delimited)
    } else {
        serializer.serialize_none()
    }
}
