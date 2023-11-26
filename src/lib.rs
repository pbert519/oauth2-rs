#![cfg_attr(not(feature = "reqwest"), no_std)]
#![warn(missing_docs)]
//!
//! An strongly-typed implementation of OAuth2
//! ([RFC 6749](https://tools.ietf.org/html/rfc6749)) Device code flow
//!
//! # Contents
//! * [Importing `oauth2`: selecting an HTTP client interface](#importing-oauth2-selecting-an-http-client-interface)
//! * [Device Code Flow](#device-code-flow)
//! * [Other examples](#other-examples)
//!
//! # Importing `oauth2`: selecting an HTTP client interface
//!
//! This library offers a flexible HTTP client interface:
//!  * **Synchronous (blocking)**
//!
//! For the HTTP client modes described above, the following HTTP client implementations can be
//! used:
//!  * **[`reqwest`]**
//!
//!    The `reqwest` HTTP client supports both the synchronous and asynchronous modes and is enabled
//!    by default.
//!
//!    Synchronous client: [`reqwest::http_client`]
//!
//!  * **Custom**
//!
//!    In addition to the clients above, users may define their own HTTP clients, which must accept
//!    an [`HttpRequest`] and return an [`HttpResponse`] or error. Users writing their own clients
//!    may wish to disable the default `reqwest` dependency by specifying
//!    `default-features = false` in `Cargo.toml` (replacing `...` with the desired version of this
//!    crate):
//!    ```toml
//!    oauth2 = { version = "...", default-features = false }
//!    ```
//!
//!    Synchronous HTTP clients should implement the following trait:
//!    ```rust,ignore
//!    FnOnce(HttpRequest) -> Result<HttpResponse, RE>
//!    where RE: std::error::Error + 'static
//!    ```
//!
//! # Getting started
//!
//!
//!
//! # Device Code Flow
//!
//! Device Code Flow allows users to sign in on browserless or input-constrained
//! devices.  This is a two-stage process; first a user-code and verification
//! URL are obtained by using the `Client::exchange_client_credentials`
//! method. Those are displayed to the user, then are used in a second client
//! to poll the token endpoint for a token.
//!
//! ## Example
//!
//! ```rust,no_run
//! use anyhow;
//! use oauth2::{
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     DeviceAuthorizationUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2::devicecode::StandardDeviceAuthorizationResponse;
//! use oauth2::reqwest::http_client;
//!
//! # fn err_wrapper() -> Result<(), anyhow::Error> {
//! let device_auth_url = DeviceAuthorizationUrl::new("http://deviceauth".to_string());
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string()),
//!         Some(TokenUrl::new("http://token".to_string())),
//!     )
//!     .set_device_authorization_url(device_auth_url);
//!
//! let details: StandardDeviceAuthorizationResponse = client
//!     .exchange_device_code().unwrap()
//!     .add_scope(Scope::new("read".to_string()))
//!     .request(http_client).unwrap();
//!
//! println!(
//!     "Open this URL in your browser:\n{}\nand enter the code: {}",
//!     details.verification_uri().to_string(),
//!     details.user_code().secret().to_string()
//! );
//!
//! let token_result =
//!     client
//!     .exchange_device_access_token(&details)
//!     .request(http_client, std::thread::sleep, None).unwrap();
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Other examples
//!
//! More specific implementations are available as part of the examples:
//!
//! - [Microsoft Device Code Flow (async)](https://github.com/ramosbugs/oauth2-rs/blob/main/examples/microsoft_devicecode.rs)

use core::fmt::Error as FormatterError;
use core::fmt::{Debug, Display, Formatter};
use core::future::Future;
use core::marker::PhantomData;
use core::time::Duration;

use chrono::{DateTime, Utc};
use http::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::status::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::borrow::{Cow, ToOwned};
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::devicecode::DeviceAccessTokenPollResult;

///
/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
///
pub mod basic;

///
/// Device Code Flow OAuth2 implementation
/// ([RFC 8628](https://tools.ietf.org/html/rfc8628)).
///
pub mod devicecode;

///
/// Helper methods used by OAuth2 implementations/extensions.
///
pub mod helpers;

///
/// HTTP client backed by the [reqwest](https://crates.io/crates/reqwest) crate.
/// Requires "reqwest" feature.
///
#[cfg(feature = "reqwest")]
pub mod reqwest;

#[cfg(test)]
mod tests;

mod types;

///
/// Public re-exports of types used for HTTP client interfaces.
///
pub use http;

pub use devicecode::{
    DeviceAuthorizationResponse, DeviceCodeErrorResponse, DeviceCodeErrorResponseType,
    EmptyExtraDeviceAuthorizationFields, ExtraDeviceAuthorizationFields,
    StandardDeviceAuthorizationResponse,
};

pub use types::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, DeviceAuthorizationUrl,
    DeviceCode, EndUserVerificationUrl, RefreshToken, ResponseType, Scope, TokenUrl, UserCode,
};

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

///
/// There was a problem configuring the request.
///
#[non_exhaustive]
#[derive(Debug)]
pub enum ConfigurationError {
    ///
    /// The endpoint URL tp be contacted is missing.
    ///
    MissingUrl(&'static str),
    ///
    /// The endpoint URL to be contacted MUST be HTTPS.
    ///
    InsecureUrl(&'static str),
}

///
/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *BasicAuth*, following the recommendation of
/// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
///
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AuthType {
    /// The client_id and client_secret (if set) will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}

///
/// Stores the configuration for an OAuth2 client.
///
/// # Error Types
///
/// To enable compile time verification that only the correct and complete set of errors for the `Client` function being
/// invoked are exposed to the caller, the `Client` type is specialized on multiple implementations of the
/// [`ErrorResponse`] trait. The exact [`ErrorResponse`] implementation returned varies by the RFC that the invoked
/// `Client` function implements:
///
///   - Generic type `TE` (aka Token Error) for errors defined by [RFC 6749 OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).
#[derive(Clone, Debug)]
pub struct Client<TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_url: AuthUrl,
    auth_type: AuthType,
    token_url: Option<TokenUrl>,
    device_authorization_url: Option<DeviceAuthorizationUrl>,
    phantom: PhantomData<(TE, TR, TT)>,
}

impl<TE, TR, TT> Client<TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Initializes an OAuth2 client with the fields common to most OAuth2 flows.
    ///
    /// # Arguments
    ///
    /// * `client_id` -  Client ID
    /// * `client_secret` -  Optional client secret. A client secret is generally used for private
    ///   (server-side) OAuth2 clients and omitted from public (client-side or native app) OAuth2
    ///   clients (see [RFC 8252](https://tools.ietf.org/html/rfc8252)).
    /// * `auth_url` -  Authorization endpoint: used by the client to obtain authorization from
    ///   the resource owner via user-agent redirection. This URL is used in all standard OAuth2
    ///   flows except the [Resource Owner Password Credentials
    ///   Grant](https://tools.ietf.org/html/rfc6749#section-4.3) and the
    ///   [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4).
    /// * `token_url` - Token endpoint: used by the client to exchange an authorization grant
    ///   (code) for an access token, typically with client authentication. This URL is used in
    ///   all standard OAuth2 flows except the
    ///   [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2). If this value is set
    ///   to `None`, the `exchange_*` methods will return `Err(RequestTokenError::Other(_))`.
    ///
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_url: AuthUrl,
        token_url: Option<TokenUrl>,
    ) -> Self {
        Client {
            client_id,
            client_secret,
            auth_url,
            auth_type: AuthType::BasicAuth,
            token_url,
            device_authorization_url: None,
            phantom: PhantomData,
        }
    }

    ///
    /// Configures the type of client authentication used for communicating with the authorization
    /// server.
    ///
    /// The default is to use HTTP Basic authentication, as recommended in
    /// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1). Note that
    /// if a client secret is omitted (i.e., `client_secret` is set to `None` when calling
    /// [`Client::new`]), [`AuthType::RequestBody`] is used regardless of the `auth_type` passed to
    /// this function.
    ///
    pub fn set_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = auth_type;

        self
    }

    ///
    /// Sets the the device authorization URL used by the device authorization endpoint.
    /// Used for Device Code Flow, as per [RFC 8628](https://tools.ietf.org/html/rfc8628).
    ///
    pub fn set_device_authorization_url(
        mut self,
        device_authorization_url: DeviceAuthorizationUrl,
    ) -> Self {
        self.device_authorization_url = Some(device_authorization_url);

        self
    }

    ///
    /// Exchanges a refresh token for an access token
    ///
    /// See <https://tools.ietf.org/html/rfc6749#section-6>.
    ///
    pub fn exchange_refresh_token<'a, 'b>(
        &'a self,
        refresh_token: &'b RefreshToken,
    ) -> RefreshTokenRequest<'b, TE, TR, TT>
    where
        'a: 'b,
    {
        RefreshTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            refresh_token,
            scopes: Vec::new(),
            token_url: self.token_url.as_ref(),
            _phantom: PhantomData,
        }
    }

    ///
    /// Perform a device authorization request as per
    /// <https://tools.ietf.org/html/rfc8628#section-3.1>.
    ///
    pub fn exchange_device_code(
        &self,
    ) -> Result<DeviceAuthorizationRequest<TE>, ConfigurationError> {
        Ok(DeviceAuthorizationRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            scopes: Vec::new(),
            device_authorization_url: self
                .device_authorization_url
                .as_ref()
                .ok_or(ConfigurationError::MissingUrl("device authorization_url"))?,
            _phantom: PhantomData,
        })
    }

    ///
    /// Perform a device access token request as per
    /// <https://tools.ietf.org/html/rfc8628#section-3.4>.
    ///
    pub fn exchange_device_access_token<'a, 'b, 'c, EF>(
        &'a self,
        auth_response: &'b DeviceAuthorizationResponse<EF>,
    ) -> DeviceAccessTokenRequest<'b, 'c, TR, TT, EF>
    where
        'a: 'b,
        EF: ExtraDeviceAuthorizationFields,
    {
        DeviceAccessTokenRequest {
            auth_type: &self.auth_type,
            client_id: &self.client_id,
            client_secret: self.client_secret.as_ref(),
            extra_params: Vec::new(),
            token_url: self.token_url.as_ref(),
            dev_auth_resp: auth_response,
            time_fn: Arc::new(Utc::now),
            max_backoff_interval: None,
            _phantom: PhantomData,
        }
    }

    ///
    /// Returns the Client ID.
    ///
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    ///
    /// Returns the authorization endpoint.
    ///
    pub fn auth_url(&self) -> &AuthUrl {
        &self.auth_url
    }

    ///
    /// Returns the type of client authentication used for communicating with the authorization
    /// server.
    ///
    pub fn auth_type(&self) -> &AuthType {
        &self.auth_type
    }

    ///
    /// Returns the token endpoint.
    ///
    pub fn token_url(&self) -> Option<&TokenUrl> {
        self.token_url.as_ref()
    }

    ///
    /// Returns the the device authorization URL used by the device authorization endpoint.
    ///
    pub fn device_authorization_url(&self) -> Option<&DeviceAuthorizationUrl> {
        self.device_authorization_url.as_ref()
    }
}

///
/// An HTTP request.
///
#[derive(Debug)]
pub struct HttpRequest {
    // These are all owned values so that the request can safely be passed between
    // threads.
    /// URL to which the HTTP request is being made.
    pub url: String,
    /// HTTP request method for this request.
    pub method: http::method::Method,
    /// HTTP request headers to send.
    pub headers: HeaderMap,
    /// HTTP request body (typically for POST requests only).
    pub body: Vec<u8>,
}

///
/// An HTTP response.
///
#[derive(Clone, Debug)]
pub struct HttpResponse {
    /// HTTP status code returned by the server.
    pub status_code: http::status::StatusCode,
    /// HTTP response headers returned by the server.
    pub headers: HeaderMap,
    /// HTTP response body returned by the server.
    pub body: Vec<u8>,
}

///
/// A request to exchange a refresh token for an access token.
///
/// See <https://tools.ietf.org/html/rfc6749#section-6>.
///
#[derive(Debug)]
pub struct RefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    refresh_token: &'a RefreshToken,
    scopes: Vec<Cow<'a, Scope>>,
    token_url: Option<&'a TokenUrl>,
    _phantom: PhantomData<(TE, TR, TT)>,
}
impl<'a, TE, TR, TT> RefreshTokenRequest<'a, TE, TR, TT>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse<TT>,
    TT: TokenType,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Appends a new scope to the token request.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Appends a collection of scopes to the token request.
    ///
    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.scopes.extend(scopes.into_iter().map(Cow::Owned));
        self
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F>(self, http_client: F) -> Result<TR, RequestTokenError<TE>>
    where
        F: FnOnce(HttpRequest) -> anyhow::Result<HttpResponse>,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response)
    }
    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F>(self, http_client: C) -> Result<TR, RequestTokenError<TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = anyhow::Result<HttpResponse>>,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        endpoint_response(http_response)
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestTokenError<TE>> {
        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            Some(&self.scopes),
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?
                .url(),
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", self.refresh_token.secret()),
            ],
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn endpoint_request<'a>(
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: &'a [(Cow<'a, str>, Cow<'a, str>)],
    scopes: Option<&'a Vec<Cow<'a, Scope>>>,
    url: String,
    params: Vec<(&'a str, &'a str)>,
) -> HttpRequest {
    let mut headers = HeaderMap::new();
    headers.append(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_JSON));
    headers.append(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_FORMENCODED),
    );

    let scopes_opt = scopes.and_then(|scopes| {
        if !scopes.is_empty() {
            Some(
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            None
        }
    });

    let mut params: Vec<(&str, &str)> = params;
    if let Some(ref scopes) = scopes_opt {
        params.push(("scope", scopes));
    }

    // FIXME: add support for auth extensions? e.g., client_secret_jwt and private_key_jwt
    match (auth_type, client_secret) {
        // Basic auth only makes sense when a client secret is provided. Otherwise, always pass the
        // client ID in the request body.
        (AuthType::BasicAuth, Some(secret)) => {
            // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
            // before using them as HTTP Basic auth username and password. Note that this is
            // not standard for ordinary Basic auth, so curl won't do it for us.
            let urlencoded_id: String =
                form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
            let urlencoded_secret: String =
                form_urlencoded::byte_serialize(secret.secret().as_bytes()).collect();
            let b64_credential =
                base64::encode(format!("{}:{}", &urlencoded_id, urlencoded_secret));
            headers.append(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
            );
        }
        (AuthType::RequestBody, _) | (AuthType::BasicAuth, None) => {
            params.push(("client_id", client_id));
            if let Some(client_secret) = client_secret {
                params.push(("client_secret", client_secret.secret()));
            }
        }
    }

    params.extend_from_slice(
        extra_params
            .iter()
            .map(|(k,v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    HttpRequest {
        url: url.to_owned(),
        method: http::method::Method::POST,
        headers,
        body,
    }
}

fn endpoint_response<TE, DO>(http_response: HttpResponse) -> Result<DO, RequestTokenError<TE>>
where
    TE: ErrorResponse,
    DO: DeserializeOwned,
{
    check_response_status(&http_response)?;

    check_response_body(&http_response)?;

    let response_body = http_response.body.as_slice();
    serde_json::from_slice(response_body)
        .map_err(|e| RequestTokenError::Parse(e, response_body.to_vec()))
}

fn check_response_status<TE>(http_response: &HttpResponse) -> Result<(), RequestTokenError<TE>>
where
    TE: ErrorResponse,
{
    if http_response.status_code != StatusCode::OK {
        let reason = http_response.body.as_slice();
        if reason.is_empty() {
            return Err(RequestTokenError::Other(
                "Server returned empty error response".to_string(),
            ));
        } else {
            let error = match serde_json::from_slice(reason) {
                Ok(error) => RequestTokenError::ServerResponse(error),
                Err(error) => RequestTokenError::Parse(error, reason.to_vec()),
            };
            return Err(error);
        }
    }

    Ok(())
}

fn check_response_body<TE>(http_response: &HttpResponse) -> Result<(), RequestTokenError<TE>>
where
    TE: ErrorResponse,
{
    // Validate that the response Content-Type is JSON.
    http_response
        .headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if content_type.to_str().ok().filter(|ct| ct.to_lowercase().starts_with(CONTENT_TYPE_JSON)).is_none() {
                Err(
                    RequestTokenError::Other(
                        format!(
                            "Unexpected response Content-Type: {:?}, should be `{}`",
                            content_type,
                            CONTENT_TYPE_JSON
                        )
                    )
                )
            } else {
                Ok(())
            }
        )?;

    if http_response.body.is_empty() {
        return Err(RequestTokenError::Other(
            "Server returned empty response body".to_string(),
        ));
    }

    Ok(())
}

///
/// The request for a set of verification codes from the authorization server.
///
/// See <https://tools.ietf.org/html/rfc8628#section-3.1>.
///
#[derive(Debug)]
pub struct DeviceAuthorizationRequest<'a, TE>
where
    TE: ErrorResponse,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    scopes: Vec<Cow<'a, Scope>>,
    device_authorization_url: &'a DeviceAuthorizationUrl,
    _phantom: PhantomData<TE>,
}

impl<'a, TE> DeviceAuthorizationRequest<'a, TE>
where
    TE: ErrorResponse + 'static,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Appends a new scope to the token request.
    ///
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    ///
    /// Appends a collection of scopes to the token request.
    ///
    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.scopes.extend(scopes.into_iter().map(Cow::Owned));
        self
    }

    fn prepare_request(self) -> Result<HttpRequest, RequestTokenError<TE>> {
        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            Some(&self.scopes),
            self.device_authorization_url.url(),
            vec![],
        ))
    }

    ///
    /// Synchronously sends the request to the authorization server and awaits a response.
    ///
    pub fn request<F, EF>(
        self,
        http_client: F,
    ) -> Result<DeviceAuthorizationResponse<EF>, RequestTokenError<TE>>
    where
        F: FnOnce(HttpRequest) -> anyhow::Result<HttpResponse>,
        EF: ExtraDeviceAuthorizationFields,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestTokenError::Request)
            .and_then(endpoint_response)
    }

    ///
    /// Asynchronously sends the request to the authorization server and returns a Future.
    ///
    pub async fn request_async<C, F, EF>(
        self,
        http_client: C,
    ) -> Result<DeviceAuthorizationResponse<EF>, RequestTokenError<TE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = anyhow::Result<HttpResponse>>,
        EF: ExtraDeviceAuthorizationFields,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestTokenError::Request)?;
        endpoint_response(http_response)
    }
}

///
/// The request for an device access token from the authorization server.
///
/// See <https://tools.ietf.org/html/rfc8628#section-3.4>.
///
#[derive(Clone)]
pub struct DeviceAccessTokenRequest<'a, 'b, TR, TT, EF>
where
    TR: TokenResponse<TT>,
    TT: TokenType,
    EF: ExtraDeviceAuthorizationFields,
{
    auth_type: &'a AuthType,
    client_id: &'a ClientId,
    client_secret: Option<&'a ClientSecret>,
    extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    token_url: Option<&'a TokenUrl>,
    dev_auth_resp: &'a DeviceAuthorizationResponse<EF>,
    time_fn: Arc<dyn Fn() -> DateTime<Utc> + 'b + Send + Sync>,
    max_backoff_interval: Option<Duration>,
    _phantom: PhantomData<(TR, TT, EF)>,
}

impl<'a, 'b, TR, TT, EF> DeviceAccessTokenRequest<'a, 'b, TR, TT, EF>
where
    TR: TokenResponse<TT>,
    TT: TokenType,
    EF: ExtraDeviceAuthorizationFields,
{
    ///
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    ///
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    ///
    /// Specifies a function for returning the current time.
    ///
    /// This function is used while polling the authorization server.
    ///
    pub fn set_time_fn<T>(mut self, time_fn: T) -> Self
    where
        T: Fn() -> DateTime<Utc> + 'b + Send + Sync,
    {
        self.time_fn = Arc::new(time_fn);
        self
    }

    ///
    /// Sets the upper limit of the sleep interval to use for polling the token endpoint when the
    /// HTTP client returns an error (e.g., in case of connection timeout).
    ///
    pub fn set_max_backoff_interval(mut self, interval: Duration) -> Self {
        self.max_backoff_interval = Some(interval);
        self
    }

    ///
    /// Synchronously polls the authorization server for a response, waiting
    /// using a user defined sleep function.
    ///
    pub fn request<F, S>(
        self,
        http_client: F,
        sleep_fn: S,
        timeout: Option<Duration>,
    ) -> Result<TR, RequestTokenError<DeviceCodeErrorResponse>>
    where
        F: Fn(HttpRequest) -> anyhow::Result<HttpResponse>,
        S: Fn(Duration),
    {
        // Get the request timeout and starting interval
        let timeout_dt = self.compute_timeout(timeout)?;
        let mut interval = self.dev_auth_resp.interval();

        // Loop while requesting a token.
        loop {
            let now = (*self.time_fn)();
            if now > timeout_dt {
                break Err(RequestTokenError::ServerResponse(
                    DeviceCodeErrorResponse::new(
                        DeviceCodeErrorResponseType::ExpiredToken,
                        Some(String::from("This device code has expired.")),
                        None,
                    ),
                ));
            }

            match self.process_response(http_client(self.prepare_request()?), interval) {
                DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval) => {
                    interval = new_interval
                }
                DeviceAccessTokenPollResult::Done(res, _) => break res,
            }

            // Sleep here using the provided sleep function.
            sleep_fn(interval);
        }
    }

    ///
    /// Asynchronously sends the request to the authorization server and awaits a response.
    ///
    pub async fn request_async<C, F, S, SF>(
        self,
        http_client: C,
        sleep_fn: S,
        timeout: Option<Duration>,
    ) -> Result<TR, RequestTokenError<DeviceCodeErrorResponse>>
    where
        C: Fn(HttpRequest) -> F,
        F: Future<Output = anyhow::Result<HttpResponse>>,
        S: Fn(Duration) -> SF,
        SF: Future<Output = ()>,
    {
        // Get the request timeout and starting interval
        let timeout_dt = self.compute_timeout(timeout)?;
        let mut interval = self.dev_auth_resp.interval();

        // Loop while requesting a token.
        loop {
            let now = (*self.time_fn)();
            if now > timeout_dt {
                break Err(RequestTokenError::ServerResponse(
                    DeviceCodeErrorResponse::new(
                        DeviceCodeErrorResponseType::ExpiredToken,
                        Some(String::from("This device code has expired.")),
                        None,
                    ),
                ));
            }

            match self.process_response(http_client(self.prepare_request()?).await, interval) {
                DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval) => {
                    interval = new_interval
                }
                DeviceAccessTokenPollResult::Done(res, _) => break res,
            }

            // Sleep here using the provided sleep function.
            sleep_fn(interval).await;
        }
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestTokenError<DeviceCodeErrorResponse>> {
        Ok(endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            self.token_url
                .ok_or_else(|| RequestTokenError::Other("no token_url provided".to_string()))?
                .url(),
            vec![
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", self.dev_auth_resp.device_code().secret()),
            ],
        ))
    }

    fn process_response(
        &self,
        res: anyhow::Result<HttpResponse>,
        current_interval: Duration,
    ) -> DeviceAccessTokenPollResult<TR, DeviceCodeErrorResponse, TT> {
        let http_response = match res {
            Ok(inner) => inner,
            Err(_) => {
                // RFC 8628 requires a backoff in cases of connection timeout, but we can't
                // distinguish between connection timeouts and other HTTP client request errors
                // here. Set a maximum backoff so that the client doesn't effectively backoff
                // infinitely when there are network issues unrelated to server load.
                const DEFAULT_MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(10);
                let new_interval = core::cmp::min(
                    current_interval.checked_mul(2).unwrap_or(current_interval),
                    self.max_backoff_interval
                        .unwrap_or(DEFAULT_MAX_BACKOFF_INTERVAL),
                );
                return DeviceAccessTokenPollResult::ContinueWithNewPollInterval(new_interval);
            }
        };

        // Explicitly process the response with a DeviceCodeErrorResponse
        let res = endpoint_response::<DeviceCodeErrorResponse, TR>(http_response);
        match res {
            // On a ServerResponse error, the error needs inspecting as a DeviceCodeErrorResponse
            // to work out whether a retry needs to happen.
            Err(RequestTokenError::ServerResponse(dcer)) => {
                match dcer.error() {
                    // On AuthorizationPending, a retry needs to happen with the same poll interval.
                    DeviceCodeErrorResponseType::AuthorizationPending => {
                        DeviceAccessTokenPollResult::ContinueWithNewPollInterval(current_interval)
                    }
                    // On SlowDown, a retry needs to happen with a larger poll interval.
                    DeviceCodeErrorResponseType::SlowDown => {
                        DeviceAccessTokenPollResult::ContinueWithNewPollInterval(
                            current_interval + Duration::from_secs(5),
                        )
                    }

                    // On any other error, just return the error.
                    _ => DeviceAccessTokenPollResult::Done(
                        Err(RequestTokenError::ServerResponse(dcer)),
                        PhantomData,
                    ),
                }
            }

            // On any other success or failure, return the failure.
            res => DeviceAccessTokenPollResult::Done(res, PhantomData),
        }
    }

    fn compute_timeout(
        &self,
        timeout: Option<Duration>,
    ) -> Result<DateTime<Utc>, RequestTokenError<DeviceCodeErrorResponse>> {
        // Calculate the request timeout - if the user specified a timeout,
        // use that, otherwise use the value given by the device authorization
        // response.
        let timeout_dur = timeout.unwrap_or_else(|| self.dev_auth_resp.expires_in());
        let chrono_timeout = chrono::Duration::from_std(timeout_dur)
            .map_err(|_| RequestTokenError::Other("Failed to convert duration".to_string()))?;

        // Calculate the DateTime at which the request times out.
        let timeout_dt = (*self.time_fn)()
            .checked_add_signed(chrono_timeout)
            .ok_or_else(|| RequestTokenError::Other("Failed to calculate timeout".to_string()))?;

        Ok(timeout_dt)
    }
}

///
/// Trait for OAuth2 access tokens.
///
pub trait TokenType: Clone + DeserializeOwned + Debug + PartialEq + Serialize {}

///
/// Trait for adding extra fields to the `TokenResponse`.
///
pub trait ExtraTokenFields: DeserializeOwned + Debug + Serialize {}

///
/// Empty (default) extra token fields.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmptyExtraTokenFields {}
impl ExtraTokenFields for EmptyExtraTokenFields {}

///
/// Common methods shared by all OAuth2 token implementations.
///
/// The methods in this trait are defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1). This trait exists
/// separately from the `StandardTokenResponse` struct to support customization by clients,
/// such as supporting interoperability with non-standards-complaint OAuth2 providers.
///
pub trait TokenResponse<TT>: Debug + DeserializeOwned + Serialize
where
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken;
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT;
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration>;
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken>;
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>>;
}

///
/// Standard OAuth2 token response.
///
/// This struct includes the fields defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1), as well as
/// extensions defined by the `EF` type parameter.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}
impl<EF, TT> StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// Instantiate a new OAuth2 token response.
    ///
    pub fn new(access_token: AccessToken, token_type: TT, extra_fields: EF) -> Self {
        Self {
            access_token,
            token_type,
            expires_in: None,
            refresh_token: None,
            scopes: None,
            extra_fields,
        }
    }

    ///
    /// Set the `access_token` field.
    ///
    pub fn set_access_token(&mut self, access_token: AccessToken) {
        self.access_token = access_token;
    }

    ///
    /// Set the `token_type` field.
    ///
    pub fn set_token_type(&mut self, token_type: TT) {
        self.token_type = token_type;
    }

    ///
    /// Set the `expires_in` field.
    ///
    pub fn set_expires_in(&mut self, expires_in: Option<&Duration>) {
        self.expires_in = expires_in.map(Duration::as_secs);
    }

    ///
    /// Set the `refresh_token` field.
    ///
    pub fn set_refresh_token(&mut self, refresh_token: Option<RefreshToken>) {
        self.refresh_token = refresh_token;
    }

    ///
    /// Set the `scopes` field.
    ///
    pub fn set_scopes(&mut self, scopes: Option<Vec<Scope>>) {
        self.scopes = scopes;
    }

    ///
    /// Extra fields defined by the client application.
    ///
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }

    ///
    /// Set the extra fields defined by the client application.
    ///
    pub fn set_extra_fields(&mut self, extra_fields: EF) {
        self.extra_fields = extra_fields;
    }
}
impl<EF, TT> TokenResponse<TT> for StandardTokenResponse<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    ///
    fn token_type(&self) -> &TT {
        &self.token_type
    }
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scope of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

///
/// Server Error Response
///
/// This trait exists separately from the `StandardErrorResponse` struct
/// to support customization by clients, such as supporting interoperability with
/// non-standards-complaint OAuth2 providers
///
pub trait ErrorResponse: Debug + DeserializeOwned + Serialize {}

///
/// Error types enum.
///
/// NOTE: The serialization must return the `snake_case` representation of
/// this error type. This value must match the error type from the relevant OAuth 2.0 standards
/// (RFC 6749 or an extension).
///
pub trait ErrorResponseType: Debug + DeserializeOwned + Serialize {}

///
/// Error response returned by server after requesting an access token.
///
/// The fields in this structure are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2). This
/// trait is parameterized by a `ErrorResponseType` to support error types specific to future OAuth2
/// authentication schemes and extensions.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StandardErrorResponse<T: ErrorResponseType> {
    #[serde(bound = "T: ErrorResponseType")]
    error: T,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

impl<T: ErrorResponseType> StandardErrorResponse<T> {
    ///
    /// Instantiate a new `ErrorResponse`.
    ///
    /// # Arguments
    ///
    /// * `error` - REQUIRED. A single ASCII error code deserialized to the generic parameter.
    ///   `ErrorResponseType`.
    /// * `error_description` - OPTIONAL. Human-readable ASCII text providing additional
    ///   information, used to assist the client developer in understanding the error that
    ///   occurred. Values for this parameter MUST NOT include characters outside the set
    ///   `%x20-21 / %x23-5B / %x5D-7E`.
    /// * `error_uri` - OPTIONAL. A URI identifying a human-readable web page with information
    ///   about the error used to provide the client developer with additional information about
    ///   the error. Values for the "error_uri" parameter MUST conform to the URI-reference
    ///   syntax and thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    pub fn new(error: T, error_description: Option<String>, error_uri: Option<String>) -> Self {
        Self {
            error,
            error_description,
            error_uri,
        }
    }

    ///
    /// REQUIRED. A single ASCII error code deserialized to the generic parameter
    /// `ErrorResponseType`.
    ///
    pub fn error(&self) -> &T {
        &self.error
    }
    ///
    /// OPTIONAL. Human-readable ASCII text providing additional information, used to assist
    /// the client developer in understanding the error that occurred. Values for this
    /// parameter MUST NOT include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`.
    ///
    pub fn error_description(&self) -> Option<&String> {
        self.error_description.as_ref()
    }
    ///
    /// OPTIONAL. URI identifying a human-readable web page with information about the error,
    /// used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and
    /// thus MUST NOT include characters outside the set `%x21 / %x23-5B / %x5D-7E`.
    ///
    pub fn error_uri(&self) -> Option<&String> {
        self.error_uri.as_ref()
    }
}

impl<T> ErrorResponse for StandardErrorResponse<T> where T: ErrorResponseType + 'static {}

impl<TE> Display for StandardErrorResponse<TE>
where
    TE: ErrorResponseType + Display,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        let mut formatted = self.error().to_string();

        if let Some(error_description) = self.error_description() {
            formatted.push_str(": ");
            formatted.push_str(error_description);
        }

        if let Some(error_uri) = self.error_uri() {
            formatted.push_str(" / See ");
            formatted.push_str(error_uri);
        }

        write!(f, "{}", formatted)
    }
}

///
/// Error encountered while requesting access token.
///
#[derive(Debug)]
pub enum RequestTokenError<T>
where
    T: ErrorResponse + 'static,
{
    ///
    /// Error response returned by authorization server. Contains the parsed `ErrorResponse`
    /// returned by the server.
    ///
    ServerResponse(T),
    ///
    /// An error occurred while sending the request or receiving the response (e.g., network
    /// connectivity failed).
    ///
    Request(anyhow::Error),
    ///
    /// Failed to parse server response. Parse errors may occur while parsing either successful
    /// or error responses.
    ///
    Parse(serde_json::error::Error, Vec<u8>),
    ///
    /// Some other type of error occurred (e.g., an unexpected server response).
    ///
    Other(String),
}
