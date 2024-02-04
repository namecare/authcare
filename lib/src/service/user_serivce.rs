use crate::model::identity::Identity;
use crate::model::identity_repository::{IdentityRepository, IdentityRepositoryError};
use crate::model::user::User;
use crate::model::user_repository::{UserRepository, UserRepositoryError};
use crate::oidc::provider::UserProvidedData;
use crate::utils::crypto::hash_password;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::task;

#[derive(Error, Debug)]
pub enum UserServiceError {
    #[error("User exist")]
    UserExists,

    #[error("Account not found")]
    AccountNotFound,

    #[error("Invalid External Identity")]
    InvalidExternalIdentity,

    #[error("Internal user data store error")]
    InternalDbError(#[from] UserRepositoryError),

    #[error("Internal identity data store error")]
    InternalIdentityDbError(#[from] IdentityRepositoryError),
}

#[derive(Clone)]
pub struct UserService {
    user_repository: Arc<dyn UserRepository + Send + Sync>,
    identity_repository: Arc<dyn IdentityRepository + Send + Sync>,
}

impl UserService {
    pub fn new(
        user_repository: Arc<dyn UserRepository + Send + Sync>,
        identity_repository: Arc<dyn IdentityRepository + Send + Sync>,
    ) -> Self {
        UserService {
            user_repository: user_repository.clone(),
            identity_repository: identity_repository.clone(),
        }
    }

    pub async fn create_user(
        &self,
        email: String,
        password: String,
    ) -> Result<User, UserServiceError> {
        let exists = self.user_repository.contains_with_email(&email).await?;
        if exists == true {
            return Err(UserServiceError::UserExists);
        }

        let hashed_password = task::spawn_blocking(move || hash_password(password.as_str()))
            .await
            .expect("Expect hashed");

        let user = User::new(email, hashed_password);
        let user = self.user_repository.add(user).await?;
        let identity_data: HashMap<String, serde_json::Value> = HashMap::from([
            ("sub".to_string(), user.id.to_string().into()),
            (
                "email".to_string(),
                user.email.clone().expect("For now we explect email").into(),
            ),
        ]);

        let idenity = Identity::new(&user, "email", identity_data);
        self.identity_repository.add(&idenity).await?;

        Ok(user)
    }

    pub async fn create_user_from_external_identity(
        &self,
        provider_data: &UserProvidedData,
        provider: &str,
    ) -> Result<User, UserServiceError> {
        let Some(meta) = &provider_data.metadata else {
            return Err(UserServiceError::InvalidExternalIdentity);
        };

        let Some(sub) = &meta.subject else {
            return Err(UserServiceError::InvalidExternalIdentity);
        };

        let emails: Vec<String> = provider_data
            .emails
            .iter()
            .map(|e| e.email.clone())
            .collect();
        let account_linking = self
            .determine_account_linking(provider, &sub, &emails)
            .await?;

        match account_linking.decision {
            AccountLinkingDecision::AccountExists => {
                let Some(user) = account_linking.user else {
                    return Err(UserServiceError::InvalidExternalIdentity);
                };

                return Ok(user);
            }
            AccountLinkingDecision::CreateAccount => {
                let user = User::new_from_provider(&emails[0]);
                let user = self.user_repository.add(user).await?;

                let idenity = Identity::new_from_provider(&user, provider, provider_data);
                self.identity_repository.add(&idenity).await?;

                return Ok(user);
            }
            AccountLinkingDecision::LinkAccount => {
                todo!()
            }
            AccountLinkingDecision::MultipleAccounts => {
                todo!()
            }
        }
    }

    pub async fn get_user(&self, id: &uuid::Uuid) -> Result<User, UserServiceError> {
        self.user_repository
            .get(id)
            .await
            .map_err(UserServiceError::InternalDbError)
    }

    pub async fn find_user(&self, email: &str) -> Result<User, UserServiceError> {
        self.user_repository
            .find_by_email(email)
            .await
            .map_err(UserServiceError::InternalDbError)
    }

    pub async fn delete_user(&self, id: &uuid::Uuid) -> Result<(), UserServiceError> {
        self.user_repository
            .delete(id)
            .await
            .map_err(UserServiceError::InternalDbError)
    }
}

#[derive(Debug, PartialEq)]
enum AccountLinkingDecision {
    AccountExists,
    CreateAccount,
    LinkAccount,
    MultipleAccounts,
}

#[derive(Debug)]
#[allow(dead_code)]
struct AccountLinkingResult {
    decision: AccountLinkingDecision,
    user: Option<User>,
    identities: Option<Vec<Identity>>,
}

impl UserService {
    async fn determine_account_linking(
        &self,
        provider: &str,
        sub: &str,
        emails: &[String],
    ) -> Result<AccountLinkingResult, UserServiceError> {
        let identity = self.identity_repository.find(&sub, provider).await;

        if let Ok(identity) = identity {
            // Account exists
            let user = self.user_repository.get(&identity.user_id).await?;

            return Ok(AccountLinkingResult {
                decision: AccountLinkingDecision::AccountExists,
                user: Some(user),
                identities: Some(vec![identity]),
            });
        } else if let Err(err) = identity {
            match &err {
                IdentityRepositoryError::InternalDbError(e) => {
                    if !matches!(e, sqlx::error::Error::RowNotFound) {
                        return Err(err.into());
                    }
                }
            }
        }

        let mut similar_identities = Vec::new();

        if !emails.is_empty() {
            similar_identities = self.identity_repository.find_all_by_email(emails).await?;
        }

        if similar_identities.is_empty() {
            // No similar identities, create a new account
            return Ok(AccountLinkingResult {
                decision: AccountLinkingDecision::CreateAccount,
                user: None,
                identities: None,
            });
        }

        let linking_identities = similar_identities.clone();

        // for identity in similar_identities {
        //     if get_account_linking_domain(&identity.provider) == new_account_linking_domain {
        //         linking_identities.push(identity);
        //     }
        // }

        if linking_identities.is_empty() {
            return Ok(AccountLinkingResult {
                decision: AccountLinkingDecision::CreateAccount,
                user: None,
                identities: None,
            });
        }

        for identity in &linking_identities[1..] {
            if identity.user_id != linking_identities[0].user_id {
                // Multiple user accounts in the same linking domain, let the caller decide
                return Ok(AccountLinkingResult {
                    decision: AccountLinkingDecision::MultipleAccounts,
                    user: None,
                    identities: Some(linking_identities),
                });
            }
        }

        let user = self
            .user_repository
            .get(&linking_identities[0].user_id)
            .await?;

        Ok(AccountLinkingResult {
            decision: AccountLinkingDecision::LinkAccount,
            user: Some(user),
            identities: Some(linking_identities),
        })
    }
}
