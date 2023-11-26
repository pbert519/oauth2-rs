use http::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::status::StatusCode;

use super::basic::*;
use super::devicecode::*;
use super::*;

fn new_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()),
        Some(TokenUrl::new("https://example.com/token".to_string())),
    )
}

fn mock_http_client(
    request_headers: Vec<(HeaderName, &'static str)>,
    request_body: &'static str,
    response: HttpResponse,
) -> impl Fn(HttpRequest) -> anyhow::Result<HttpResponse> {
    move |request: HttpRequest| {
        assert_eq!(
            request.headers,
            request_headers
                .iter()
                .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
                .collect(),
        );
        assert_eq!(&String::from_utf8(request.body).unwrap(), request_body);

        Ok(response.clone())
    }
}

#[test]
fn test_exchange_refresh_token_with_basic_auth() {
    let client = new_client().set_auth_type(AuthType::BasicAuth);
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
                body: "{\"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_exchange_refresh_token_with_json_response() {
    let client = new_client();
    let token = client
        .exchange_refresh_token(&RefreshToken::new("ccc".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=refresh_token&refresh_token=ccc",
            HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::new(),
                body: "{\
                       \"access_token\": \"12/34\", \
                       \"token_type\": \"bearer\", \
                       \"scope\": \"read write\"\
                       }"
                .to_string()
                .into_bytes(),
            },
        ))
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![
            Scope::new("read".to_string()),
            Scope::new("write".to_string()),
        ]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

mod colorful_extension {
    extern crate serde_json;

    use super::super::*;
    use std::fmt::Error as FormatterError;
    use std::fmt::{Debug, Display, Formatter};

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ColorfulTokenType {
        Green,
        Red,
    }
    impl TokenType for ColorfulTokenType {}

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    pub struct ColorfulFields {
        #[serde(rename = "shape")]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub shape: Option<String>,
        #[serde(rename = "height")]
        pub height: u32,
    }
    impl ExtraTokenFields for ColorfulFields {}

    #[derive(Clone, Deserialize, PartialEq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ColorfulErrorResponseType {
        TooDark,
        TooLight,
        WrongColorSpace,
    }

    impl ColorfulErrorResponseType {
        fn to_str(&self) -> &str {
            match self {
                ColorfulErrorResponseType::TooDark => "too_dark",
                ColorfulErrorResponseType::TooLight => "too_light",
                ColorfulErrorResponseType::WrongColorSpace => "wrong_color_space",
            }
        }
    }

    impl ErrorResponseType for ColorfulErrorResponseType {}

    impl Debug for ColorfulErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            Display::fmt(self, f)
        }
    }

    impl Display for ColorfulErrorResponseType {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            let message: &str = self.to_str();

            write!(f, "{}", message)
        }
    }

    pub type ColorfulTokenResponse = StandardTokenResponse<ColorfulFields, ColorfulTokenType>;


}

mod custom_errors {
    use std::fmt::Error as FormatterError;
    use std::fmt::{Display, Formatter};

    extern crate serde_json;

    use super::super::*;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct CustomErrorResponse {
        pub custom_error: String,
    }

    impl Display for CustomErrorResponse {
        fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
            write!(f, "Custom Error from server")
        }
    }

    impl ErrorResponse for CustomErrorResponse {}
}

#[test]
fn test_extension_serializer() {
    use self::colorful_extension::{ColorfulFields, ColorfulTokenResponse, ColorfulTokenType};
    let mut token_response = ColorfulTokenResponse::new(
        AccessToken::new("mysecret".to_string()),
        ColorfulTokenType::Red,
        ColorfulFields {
            shape: Some("circle".to_string()),
            height: 10,
        },
    );
    token_response.set_expires_in(Some(&Duration::from_secs(3600)));
    token_response.set_refresh_token(Some(RefreshToken::new("myothersecret".to_string())));
    let serialized = serde_json::to_string(&token_response).unwrap();
    assert_eq!(
        "{\
         \"access_token\":\"mysecret\",\
         \"token_type\":\"red\",\
         \"expires_in\":3600,\
         \"refresh_token\":\"myothersecret\",\
         \"shape\":\"circle\",\
         \"height\":10\
         }",
        serialized,
    );
}

#[test]
fn test_error_response_serializer() {
    assert_eq!(
        "{\"error\":\"unauthorized_client\"}",
        serde_json::to_string(&BasicErrorResponse::new(
            BasicErrorResponseType::UnauthorizedClient,
            None,
            None,
        ))
        .unwrap(),
    );

    assert_eq!(
        "{\
         \"error\":\"invalid_client\",\
         \"error_description\":\"Invalid client_id\",\
         \"error_uri\":\"https://example.com/errors/invalid_client\"\
         }",
        serde_json::to_string(&BasicErrorResponse::new(
            BasicErrorResponseType::InvalidClient,
            Some("Invalid client_id".to_string()),
            Some("https://example.com/errors/invalid_client".to_string()),
        ))
        .unwrap(),
    );
}

#[test]
fn test_secret_redaction() {
    let secret = ClientSecret::new("top_secret".to_string());
    assert_eq!("ClientSecret([redacted])", format!("{:?}", secret));
}

fn new_device_auth_details(expires_in: u32) -> StandardDeviceAuthorizationResponse {
    let body = format!(
        "{{\
        \"device_code\": \"12345\", \
        \"verification_uri\": \"https://verify/here\", \
        \"user_code\": \"abcde\", \
        \"verification_uri_complete\": \"https://verify/here?abcde\", \
        \"expires_in\": {}, \
        \"interval\": 1 \
        }}",
        expires_in
    );

    let device_auth_url =
        DeviceAuthorizationUrl::new("https://deviceauth/here".to_string());

    let client = new_client().set_device_authorization_url(device_auth_url.clone());
    client
        .exchange_device_code()
        .unwrap()
        .add_extra_param("foo", "bar")
        .add_scope(Scope::new("openid".to_string()))
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "scope=openid&foo=bar",
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: body.into_bytes(),
            },
        ))
        .unwrap()
}

struct IncreasingTime {
    times: std::ops::RangeFrom<i64>,
}

impl IncreasingTime {
    fn new() -> Self {
        Self { times: (0..) }
    }
    fn next(&mut self) -> DateTime<Utc> {
        let next_value = self.times.next().unwrap();
        let naive = chrono::NaiveDateTime::from_timestamp(next_value, 0);
        DateTime::<Utc>::from_utc(naive, chrono::Utc)
    }
}

/// Creates a time function that increments by one second each time.
fn mock_time_fn() -> impl Fn() -> DateTime<Utc> + Send + Sync {
    let timer = std::sync::Mutex::new(IncreasingTime::new());
    move || timer.lock().unwrap().next()
}

/// Mock sleep function that doesn't actually sleep.
fn mock_sleep_fn(_: Duration) {}

#[test]
fn test_exchange_device_code_and_token() {
    let details = new_device_auth_details(3600);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(3600), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"access_token\": \"12/34\", \
                    \"token_type\": \"bearer\", \
                    \"scope\": \"openid\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![Scope::new("openid".to_string()),]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_device_token_authorization_timeout() {
    let details = new_device_auth_details(2);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(2), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"authorization_pending\", \
                    \"error_description\": \"Still waiting for user\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .err()
        .unwrap();
    match token {
        RequestTokenError::ServerResponse(msg) => assert_eq!(
            msg,
            DeviceCodeErrorResponse::new(
                DeviceCodeErrorResponseType::ExpiredToken,
                Some(String::from("This device code has expired.")),
                None,
            )
        ),
        _ => unreachable!("Error should be an expiry"),
    }
}

#[test]
fn test_device_token_access_denied() {
    let details = new_device_auth_details(2);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(2), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"access_denied\", \
                    \"error_description\": \"Access Denied\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .err()
        .unwrap();
    match token {
        RequestTokenError::ServerResponse(msg) => {
            assert_eq!(msg.error(), &DeviceCodeErrorResponseType::AccessDenied)
        }
        _ => unreachable!("Error should be Access Denied"),
    }
}

#[test]
fn test_device_token_expired() {
    let details = new_device_auth_details(2);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(2), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"expired_token\", \
                    \"error_description\": \"Token has expired\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .err()
        .unwrap();
    match token {
        RequestTokenError::ServerResponse(msg) => {
            assert_eq!(msg.error(), &DeviceCodeErrorResponseType::ExpiredToken)
        }
        _ => unreachable!("Error should be ExpiredToken"),
    }
}

fn mock_http_client_success_fail(
    request_headers: Vec<(HeaderName, &'static str)>,
    request_body: &'static str,
    failure_response: HttpResponse,
    num_failures: usize,
    success_response: HttpResponse,
) -> impl Fn(HttpRequest) -> anyhow::Result<HttpResponse> {
    let responses: Vec<HttpResponse> = std::iter::repeat(failure_response)
        .take(num_failures)
        .chain(std::iter::once(success_response))
        .collect();
    let sync_responses = std::sync::Mutex::new(responses);

    move |request: HttpRequest| {
        assert_eq!(
            request.headers,
            request_headers
                .iter()
                .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
                .collect(),
        );
        assert_eq!(&String::from_utf8(request.body).unwrap(), request_body);

        {
            let mut rsp_vec = sync_responses.lock().unwrap();
            if rsp_vec.len() == 0 {
                Err(anyhow::Error::msg("Fail"))
            } else {
                Ok(rsp_vec.remove(0))
            }
        }
    }
}

#[test]
fn test_device_token_pending_then_success() {
    let details = new_device_auth_details(20);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(20), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client_success_fail(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"authorization_pending\", \
                    \"error_description\": \"Still waiting for user\"\
                    }"
                .to_string()
                .into_bytes(),
            },
            5,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"access_token\": \"12/34\", \
                    \"token_type\": \"bearer\", \
                    \"scope\": \"openid\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![Scope::new("openid".to_string()),]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_device_token_slowdown_then_success() {
    let details = new_device_auth_details(3600);
    assert_eq!("12345", details.device_code().secret());
    assert_eq!("https://verify/here", details.verification_uri().as_str());
    assert_eq!("abcde", details.user_code().secret().as_str());
    assert_eq!(
        "https://verify/here?abcde",
        details
            .verification_uri_complete()
            .unwrap()
            .secret()
            .as_str()
    );
    assert_eq!(Duration::from_secs(3600), details.expires_in());
    assert_eq!(Duration::from_secs(1), details.interval());

    let token = new_client()
        .exchange_device_access_token(&details)
        .set_time_fn(mock_time_fn())
        .request(mock_http_client_success_fail(
            vec![
                (ACCEPT, "application/json"),
                (CONTENT_TYPE, "application/x-www-form-urlencoded"),
                (AUTHORIZATION, "Basic YWFhOmJiYg=="),
            ],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=12345",
            HttpResponse {
                status_code: StatusCode::from_u16(400).unwrap(),
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"error\": \"slow_down\", \
                    \"error_description\": \"Woah there partner\"\
                    }"
                .to_string()
                .into_bytes(),
            },
            5,
            HttpResponse {
                status_code: StatusCode::OK,
                headers: vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("application/json").unwrap(),
                )]
                .into_iter()
                .collect(),
                body: "{\
                    \"access_token\": \"12/34\", \
                    \"token_type\": \"bearer\", \
                    \"scope\": \"openid\"\
                    }"
                .to_string()
                .into_bytes(),
            },
        ),
        mock_sleep_fn,
        None)
        .unwrap();

    assert_eq!("12/34", token.access_token().secret());
    assert_eq!(BasicTokenType::Bearer, *token.token_type());
    assert_eq!(
        Some(&vec![Scope::new("openid".to_string()),]),
        token.scopes()
    );
    assert_eq!(None, token.expires_in());
    assert!(token.refresh_token().is_none());
}

#[test]
fn test_send_sync_impl() {
    fn is_sync_and_send<T: Sync + Send>() {}
    #[derive(Debug)]
    struct TestError;
    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestError")
        }
    }
    impl std::error::Error for TestError {}

    is_sync_and_send::<AccessToken>();
    is_sync_and_send::<AuthUrl>();
    is_sync_and_send::<AuthorizationCode>();
    is_sync_and_send::<ClientId>();
    is_sync_and_send::<ClientSecret>();
    is_sync_and_send::<EmptyExtraTokenFields>();
    is_sync_and_send::<HttpRequest>();
    is_sync_and_send::<HttpResponse>();
    is_sync_and_send::<RefreshToken>();
    is_sync_and_send::<
        RefreshTokenRequest<
            StandardErrorResponse<BasicErrorResponseType>,
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
        >,
    >();
    is_sync_and_send::<ResponseType>();
    is_sync_and_send::<Scope>();
    is_sync_and_send::<StandardErrorResponse<BasicErrorResponseType>>();
    is_sync_and_send::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>();
    is_sync_and_send::<TokenUrl>();

    is_sync_and_send::<AuthType>();
    is_sync_and_send::<BasicErrorResponseType>();
    is_sync_and_send::<BasicTokenType>();
    is_sync_and_send::<RequestTokenError<StandardErrorResponse<BasicErrorResponseType>>>(
    );

    is_sync_and_send::<DeviceCode>();
    is_sync_and_send::<EndUserVerificationUrl>();
    is_sync_and_send::<UserCode>();
    is_sync_and_send::<DeviceAuthorizationUrl>();
    is_sync_and_send::<StandardDeviceAuthorizationResponse>();
    is_sync_and_send::<
        DeviceAccessTokenRequest<
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            BasicTokenType,
            EmptyExtraDeviceAuthorizationFields,
        >,
    >();
    is_sync_and_send::<DeviceAuthorizationRequest<StandardErrorResponse<BasicErrorResponseType>>>();
    is_sync_and_send::<DeviceCodeErrorResponseType>();
    is_sync_and_send::<DeviceCodeErrorResponse>();
}
