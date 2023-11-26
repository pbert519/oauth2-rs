use core::convert::Into;
use core::fmt::Error as FormatterError;
use core::fmt::{Debug, Formatter};
use core::ops::Deref;

use alloc::string::String;
use alloc::string::ToString;
use serde::{Deserialize, Serialize};

macro_rules! new_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
        impl {
            $($item:tt)*
        }
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type $(#[$attr:meta])*,
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        ),
        $new_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(
            $(#[$type_attr])*
            $type
        );
        impl $name {
            $($item)*

            #[doc = $new_doc]
            pub const fn new(s: $type) -> Self {
                $name(s)
            }
        }
        impl Deref for $name {
            type Target = $type;
            fn deref(&self) -> &$type {
                &self.0
            }
        }
        impl Into<$type> for $name {
            fn into(self) -> $type {
                self.0
            }
        }
    }
}

macro_rules! new_secret_type {
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
    ) => {
        new_secret_type![
            $(#[$attr])*
            $name($type)
            impl {}
        ];
    };
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
        impl {
            $($item:tt)*
        }
    ) => {
        new_secret_type![
            $(#[$attr])*,
            $name($type),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            concat!("Get the secret contained within this `", stringify!($name), "`."),
            impl {
                $($item)*
            }
        ];
    };
    (
        $(#[$attr:meta])*,
        $name:ident($type:ty),
        $new_doc:expr,
        $secret_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(
            #[$attr]
        )*
        pub struct $name($type);
        impl $name {
            $($item)*

            #[doc = $new_doc]
            pub fn new(s: $type) -> Self {
                $name(s)
            }
            ///
            #[doc = $secret_doc]
            ///
            /// # Security Warning
            ///
            /// Leaking this value may compromise the security of the OAuth2 flow.
            ///
            pub fn secret(&self) -> &$type { &self.0 }
        }
        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
                write!(f, concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

///
/// Creates a URL-specific new type
///
/// Types created by this macro enforce during construction that the contained value represents a
/// syntactically valid URL. However, comparisons and hashes of these types are based on the string
/// representation given during construction, disregarding any canonicalization performed by the
/// underlying `Url` struct. OpenID Connect requires certain URLs (e.g., ID token issuers) to be
/// compared exactly, without canonicalization.
///
/// In addition to the raw string representation, these types include a `url` method to retrieve a
/// parsed `Url` struct.
///
macro_rules! new_url_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        new_url_type![
            @new_type_pub $(#[$attr])*,
            $name,
            concat!("Create a new `", stringify!($name), "` from a `String` to wrap a URL."),
            concat!("Create a new `", stringify!($name), "` from a `Url` to wrap a URL."),
            concat!("Return this `", stringify!($name), "` as a parsed `Url`."),
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident
        impl {
            $($item:tt)*
        }
    ) => {
        new_url_type![
            @new_type_pub $(#[$attr])*,
            $name,
            concat!("Create a new `", stringify!($name), "` from a `String` to wrap a URL."),
            concat!("Create a new `", stringify!($name), "` from a `Url` to wrap a URL."),
            concat!("Return this `", stringify!($name), "` as a parsed `Url`."),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type_pub $(#[$attr:meta])*,
        $name:ident,
        $new_doc:expr,
        $from_url_doc:expr,
        $url_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone)]
        pub struct $name(String);
        impl $name {
            #[doc = $new_doc]
            pub fn new(url: String) -> Self {
                $name(url)
            }
            #[doc = $url_doc]
            pub fn url(&self) -> String {
                self.0.clone()
            }
            $($item)*
        }
        impl Deref for $name {
            type Target = String;
            fn deref(&self) -> &String {
                &self.0
            }
        }
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
                let mut debug_trait_builder = f.debug_tuple(stringify!($name));
                debug_trait_builder.field(&self.0);
                debug_trait_builder.finish()
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::de::Deserializer<'de>,
            {
                struct UrlVisitor;
                impl<'de> ::serde::de::Visitor<'de> for UrlVisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter
                    ) -> ::core::fmt::Result {
                        formatter.write_str(stringify!($name))
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        Ok($name::new(v.to_string()))
                    }
                }
                deserializer.deserialize_str(UrlVisitor {})
            }
        }
        impl ::serde::Serialize for $name {
            fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
            where
                SE: ::serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }
        impl ::core::hash::Hash for $name {
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) -> () {
                ::core::hash::Hash::hash(&(self.0), state);
            }
        }
        impl Ord for $name {
            fn cmp(&self, other: &$name) -> ::core::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }
        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                self.0 == other.0
            }
        }
        impl Eq for $name {}
    };
}

new_type![
    ///
    /// Client identifier issued to the client during the registration process described by
    /// [Section 2.2](https://tools.ietf.org/html/rfc6749#section-2.2).
    ///
    #[derive(Deserialize, Serialize, Eq, Hash)]
    ClientId(String)
];

new_url_type![
    ///
    /// URL of the authorization server's authorization endpoint.
    ///
    AuthUrl
];
new_url_type![
    ///
    /// URL of the authorization server's token endpoint.
    ///
    TokenUrl
];
new_url_type![
    ///
    /// URL of the client's device authorization endpoint.
    ///
    DeviceAuthorizationUrl
];
new_url_type![
    ///
    /// URL of the end-user verification URI on the authorization server.
    ///
    EndUserVerificationUrl
];
new_type![
    ///
    /// Authorization endpoint response (grant) type defined in
    /// [Section 3.1.1](https://tools.ietf.org/html/rfc6749#section-3.1.1).
    ///
    #[derive(Deserialize, Serialize, Eq, Hash)]
    ResponseType(String)
];

new_type![
    ///
    /// Access token scope, as defined by the authorization server.
    ///
    #[derive(Deserialize, Serialize, Eq, Hash)]
    Scope(String)
];
impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        self
    }
}

new_secret_type![
    ///
    /// Client password issued to the client during the registration process described by
    /// [Section 2.2](https://tools.ietf.org/html/rfc6749#section-2.2).
    ///
    #[derive(Clone, Deserialize, Serialize)]
    ClientSecret(String)
];
new_secret_type![
    ///
    /// Authorization code returned from the authorization endpoint.
    ///
    #[derive(Clone, Deserialize, Serialize)]
    AuthorizationCode(String)
];
new_secret_type![
    ///
    /// Refresh token used to obtain a new access token (if supported by the authorization server).
    ///
    #[derive(Clone, Deserialize, Serialize)]
    RefreshToken(String)
];
new_secret_type![
    ///
    /// Access token returned by the token endpoint and used to access protected resources.
    ///
    #[derive(Clone, Deserialize, Serialize)]
    AccessToken(String)
];
new_secret_type![
    ///
    /// Device code returned by the device authorization endpoint and used to query the token endpoint.
    ///
    #[derive(Clone, Deserialize, Serialize)]
    DeviceCode(String)
];
new_secret_type![
    ///
    /// Verification URI returned by the device authorization endpoint and visited by the user
    /// to authorize.  Contains the user code.
    ///
    #[derive(Clone, Deserialize, Serialize)]
    VerificationUriComplete(String)
];
new_secret_type![
    ///
    /// User code returned by the device authorization endpoint and used by the user to authorize at
    /// the verification URI.
    ///
    #[derive(Clone, Deserialize, Serialize)]
    UserCode(String)
];
