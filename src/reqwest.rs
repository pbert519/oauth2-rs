pub use blocking::http_client;
mod blocking {
    use super::super::{HttpRequest, HttpResponse};

    pub use reqwest;
    use reqwest::blocking;
    use reqwest::redirect::Policy as RedirectPolicy;

    use std::io::Read;

    ///
    /// Synchronous HTTP client.
    ///
    pub fn http_client(request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let client = blocking::Client::builder()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(RedirectPolicy::none())
            .build()?;

        let mut request_builder = client
            .request(request.method, request.url.as_str())
            .body(request.body);

        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
        let mut response = client.execute(request_builder.build()?)?;

        let mut body = Vec::new();
        response.read_to_end(&mut body)?;

        {
            Ok(HttpResponse {
                status_code: response.status(),
                headers: response.headers().to_owned(),
                body,
            })
        }
    }
}
