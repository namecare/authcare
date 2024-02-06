use openidconnect::core::{CoreClient, CoreIdTokenVerifier, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{ClaimsVerificationError, ClientId, ClientSecret, IssuerUrl, Nonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::oidc::provider::apple::{ISSUER_APPLE, parse_apple_id_token_claims};

use crate::oidc::provider::google::{ISSUER_GOOGLE, parse_google_id_token_claims};
use crate::oidc::provider::UserProvidedData;



#[derive(Error, Debug)]
pub enum OidcError {
    #[error("Verification error")]
    VerificationError(#[from] ClaimsVerificationError),

    #[error("Serialization error")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("DiscoveryError")]
    DiscoveryError,

    #[error("UnknownProvider")]
    UnknownProvider,
}

#[derive(Debug, Clone, Deserialize, Serialize, Hash, PartialEq, Eq)]
pub enum OidcProvider {
    #[serde(rename = "apple")]
    Apple,

    #[serde(rename = "google")]
    Google
}

impl OidcProvider {
    pub fn issuer_url(&self) -> &'static str {
        match self {
            OidcProvider::Apple => return ISSUER_APPLE,
            OidcProvider::Google => return ISSUER_GOOGLE
        }
    }

    pub async fn fetch_provider_metadata(&self) -> Result<CoreProviderMetadata, OidcError> {
        let issuer_url = self.issuer_url();
        Self::discover_provider_metadata(issuer_url).await
    }

    async fn discover_provider_metadata(issuer_url: &str) -> Result<CoreProviderMetadata, OidcError> {
        let Ok(issuer_url) = IssuerUrl::new(issuer_url.to_string()) else {
            return Err(OidcError::DiscoveryError)
        };

        let Ok(provider_metadata) = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string()).expect("Expect"),
            async_http_client,
        ).await else {
            return Err(OidcError::DiscoveryError)
        };

        Ok(provider_metadata)
    }

    pub fn name(&self) -> &'static str {
        match self {
            OidcProvider::Apple => return "apple",
            OidcProvider::Google => return "google"
        }
    }
}
pub struct OidcClient {
    client: CoreClient,
    issuer_url: String
}

impl OidcClient {
    pub fn new(provider_metadata: CoreProviderMetadata, client_id: String, secret: Option<String>) -> OidcClient {
        let secret = secret.map(| v| ClientSecret::new(v));
        let client_id = ClientId::new(client_id);
        let issuer_url = provider_metadata.issuer().to_string();

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            client_id,
            secret,
        );

        OidcClient {
            client,
            issuer_url
        }
    }

    pub fn verify(&self, jwt: &str, nonce: Option<String>) -> Result<UserProvidedData, OidcError> {
        let issuer = self.issuer_url.as_str();
        let verifier: CoreIdTokenVerifier = self.client.id_token_verifier();

        let nonce_verifier: Box<dyn FnOnce(Option<&Nonce>) -> Result<(), String>> =
            Box::new(|n: Option<&Nonce>| match nonce {
                None => Ok(()),
                Some(nonce) => {
                    let Some(n) = n else {
                        return Err("missing nonce claim".to_string());
                    };

                    if &Nonce::new(nonce) == n {
                        Ok(())
                    } else {
                        Err("nonce mismatch".to_string())
                    }
                }
            });

        let user_provided_data = match issuer {
            ISSUER_GOOGLE => parse_google_id_token_claims(&verifier, nonce_verifier, jwt)?,
            ISSUER_APPLE => parse_apple_id_token_claims(&verifier, nonce_verifier, jwt)?,
            _ => return Err(OidcError::UnknownProvider)
        };

        Ok(user_provided_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    #[tokio::test]
    fn test_verify_signature() {
        let token = "eyJraWQiOiJXNldjT0tCIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiYXBwLm5hbWVjYXJlLmlvcyIsImV4cCI6MTY4OTYyOTk3MSwiaWF0IjoxNjg5NTQzNTcxLCJzdWIiOiIwMDEwOTEuMjJjMGNhNTk0ZDQyNDNjNThlZGYzNTUzNTQwMzgwYjUuMjA0NSIsImNfaGFzaCI6Ik8xeUVwY1dQbExDdXU4NnFrbGtvRmciLCJlbWFpbCI6ImVjcjlwYmhpbXVAcHJpdmF0ZXJlbGF5LmFwcGxlaWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIiwiaXNfcHJpdmF0ZV9lbWFpbCI6InRydWUiLCJhdXRoX3RpbWUiOjE2ODk1NDM1NzEsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.WvnvubpILn6cGNeEdh_Jqy18Q9h_OHz0pRnva6ZtAt6POnj_QqTQt1zola8fB5L1FMgbytGEnFxPW9sLuSYXGMEDtAl7-Wex3BSIzTOJBQqpz_HL3zVTInLAlNU36cBPUN0hhhe027T5__Hx1Ptcjwpj9RKpiPGoHRPB_MrhULL2djS_seFcpZaG01-Y5sPiQKpJVVjDECxnvO1OXDtL-FWQLUALAIFLFaIdYwrX0kncmcusHzZEa0DzGG9rfJ-J0Y_jFKmaUkHLpeWuxKV_0H_DQn1zDOy8fuB9MVFIo9FRUjuCxPXXmttT3WyeqCH2_iUM5jmEUkge78V6g68qSw";

        let keys_json = r#"{
                                  "keys": [
                                    {
                                      "kty": "RSA",
                                      "kid": "W6WcOKB",
                                      "use": "sig",
                                      "alg": "RS256",
                                      "n": "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw",
                                      "e": "AQAB"
                                    },
                                    {
                                      "kty": "RSA",
                                      "kid": "fh6Bs8C",
                                      "use": "sig",
                                      "alg": "RS256",
                                      "n": "u704gotMSZc6CSSVNCZ1d0S9dZKwO2BVzfdTKYz8wSNm7R_KIufOQf3ru7Pph1FjW6gQ8zgvhnv4IebkGWsZJlodduTC7c0sRb5PZpEyM6PtO8FPHowaracJJsK1f6_rSLstLdWbSDXeSq7vBvDu3Q31RaoV_0YlEzQwPsbCvD45oVy5Vo5oBePUm4cqi6T3cZ-10gr9QJCVwvx7KiQsttp0kUkHM94PlxbG_HAWlEZjvAlxfEDc-_xZQwC6fVjfazs3j1b2DZWsGmBRdx1snO75nM7hpyRRQB4jVejW9TuZDtPtsNadXTr9I5NjxPdIYMORj9XKEh44Z73yfv0gtw",
                                      "e": "AQAB"
                                    },
                                    {
                                      "kty": "RSA",
                                      "kid": "YuyXoY",
                                      "use": "sig",
                                      "alg": "RS256",
                                      "n": "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
                                      "e": "AQAB"
                                    }
                                  ]
                                }"#;

        let client = oidc_client("https://appleid.apple.com", "app.namecare.ios");
    }
}
