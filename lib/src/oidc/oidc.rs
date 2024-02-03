use chrono::{DateTime, Utc};
use openidconnect::core::{CoreClient, CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata};
use openidconnect::{ClaimsVerificationError, ClientId, IssuerUrl, Nonce};
use openidconnect::reqwest::{async_http_client};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::str::FromStr;

use crate::oidc::provider::{UserProvidedData};
use crate::oidc::provider::apple::parse_apple_id_token_claims;

use crate::oidc::serde_string_bool;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("Verification error")]
    VerificationError(#[from] ClaimsVerificationError),

    #[error("Serialization error")]
    SerdeJsonError(#[from] serde_json::Error)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct AdditionalClaims {

    #[serde(deserialize_with = "serde_string_bool::deserialize")]
    pub is_private_email: bool,
    pub auth_time: Option<DateTime<Utc>>,
}

impl openidconnect::AdditionalClaims for AdditionalClaims {}

pub type IdToken = openidconnect::IdToken<
    AdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub struct OidcClient {
    client: CoreClient
}

impl OidcClient {
    pub async fn new(issuer_url: &str, client_id: &str) -> OidcClient {
        let issuer_url = IssuerUrl::new(issuer_url.to_string()).expect("Invalid issuer URL");

        let provider_metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(issuer_url.to_string()).expect("Expect"), async_http_client).await
            .unwrap_or_else(|_| {
                panic!("Failed to discover OpenID Provider");
            });

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_string()),
            None,
        );

        OidcClient {
            client
        }
    }

    pub fn verify(&self, jwt: &str, nonce: Option<String>) -> Result<UserProvidedData, OidcError> {
        let verifier = self.client.id_token_verifier();

        let nonce_verifier: Box<dyn FnOnce(Option<&Nonce>) -> Result<(), String>> = Box::new(|n: Option<&Nonce>| {
            match nonce {
                None => Ok(()),
                Some(nonce) => {
                    let Some(n) = n else { return Err("missing nonce claim".to_string()); };

                    if &Nonce::new(nonce) == n {
                        Ok(())
                    }else{
                        Err("nonce mismatch".to_string())
                    }
                }
            }
        });

        let token = IdToken::from_str(jwt)?;
        let claims = token.claims(&verifier, nonce_verifier)?;
        Ok(parse_apple_id_token_claims(&claims)?)
    }
}


#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};
    use super::*;

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
