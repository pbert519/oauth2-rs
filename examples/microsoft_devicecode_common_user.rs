use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::{AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenUrl};
use oauth2::reqwest::http_client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let device_auth_url = DeviceAuthorizationUrl::new(
        "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string(),
    );
    let client = BasicClient::new(
        ClientId::new("client_id".to_string()),
        None,
        AuthUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string()),
        Some(TokenUrl::new(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
        )),
    )
    .set_device_authorization_url(device_auth_url);

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code().unwrap()
        .add_scope(Scope::new("read".to_string()))
        .request(http_client)
        .unwrap();

    eprintln!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        details.verification_uri().to_string(),
        details.user_code().secret().to_string()
    );

    let token_result = client
        .exchange_device_access_token(&details)
        .request(http_client, std::thread::sleep, None)
        .unwrap();

    eprintln!("Token:{:?}", token_result);

    Ok(())
}
