use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::reqwest::http_client;
use oauth2::{AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, TokenUrl};
use std::error::Error;

// Reference: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
// Please use your tenant id when using this example
const TENANT_ID: &str = "{tenant}";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let device_auth_url = DeviceAuthorizationUrl::new(format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
        TENANT_ID
    ));
    let client = BasicClient::new(
        ClientId::new("client_id".to_string()),
        None,
        AuthUrl::new(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            TENANT_ID
        )),
        Some(TokenUrl::new(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            TENANT_ID
        ))),
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
