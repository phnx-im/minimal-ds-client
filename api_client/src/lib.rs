// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # API Client
//!
//! This crate provides a client to interact with the Minimal DS API.
//!
//! ## Usage
//!
//! To start interacting with the DS, create an [`UnregisteredApiClient`] with
//! the URL of the DS. Then call `register` with the key packages of the client
//! to register the client with the DS. The returned [`ApiClient`] provides the
//! necessary methods to interact with the DS.
//!
//! Inputs to the methods can be generated using the `openmls` crate. See that
//! crate's documentation for further guidance.

use errors::{
    CreateGroupError, DeleteClientError, DeleteGroupError, DistributeGroupMessageError,
    DistributeWelcomeError, FetchKeyPackageError, FetchMessagesError, ListClientsError,
    RegisterClientError, SendMessageError, UploadKeyPackagesError,
};
use minimal_ds_types::{
    requests::{
        DeleteClientRequest, DeleteGroupRequest, FetchKeyPackageRequest, FetchMessagesRequest,
    },
    AuthToken, ClientCredentials,
};
use mls_assist::messages::{AssistedMessageError, AssistedMessageOut};
use openmls::{
    framing::{MlsMessageBodyOut, MlsMessageIn, MlsMessageOut},
    key_packages::KeyPackageIn,
    prelude::{
        tls_codec::{self, Serialize},
        DeserializeBytes,
    },
    treesync::RatchetTree,
};
use requests::{MinimalDsMessageOut, MinimalDsResponseIn, RegisterClientRequestOut};
use reqwest::{Client, Url};

// Re-export types
pub use minimal_ds_types::{DsClientId, DsGroupId};

pub mod errors;
pub mod requests;

#[derive(Clone)]
struct DsConnection {
    client: Client,
    // For now we assume there's only one DS we can connect to.
    ds_url: Url,
}

impl DsConnection {
    fn new(ds_url: Url) -> Self {
        let client = Client::new();
        Self { client, ds_url }
    }

    async fn send_message(
        &self,
        message: MinimalDsMessageOut<'_>,
    ) -> Result<MinimalDsResponseIn, SendMessageError> {
        let message_bytes = message.tls_serialize_detached()?;
        let response = self
            .client
            .post(self.ds_url.clone())
            .body(message_bytes)
            .send()
            .await?;
        match response.status() {
            reqwest::StatusCode::OK => {
                let response_bytes = response.bytes().await?;
                let response = MinimalDsResponseIn::tls_deserialize_exact_bytes(&response_bytes)?;
                Ok(response)
            }
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                let error_string = response.text().await?;
                Err(SendMessageError::MinimalDsError(error_string))
            }
            other => Err(SendMessageError::NetworkError(other)),
        }
    }
}

/// An API client that is not yet registered with the DS. Call `register` to
/// register the client and obtain an [`ApiClient`].
pub struct UnregisteredApiClient {
    connection: DsConnection,
}

impl UnregisteredApiClient {
    /// Create a new API client that is not yet registered with the DS.
    pub fn new(ds_url: Url) -> Self {
        let connection = DsConnection::new(ds_url);
        Self { connection }
    }

    /// Register the client with the DS. The client will be registered with the
    /// key packages provided in `key_packages` and `last_resort_key_package`.
    pub async fn register(
        &self,
        key_packages: &[MlsMessageOut],
        last_resort_key_package: &MlsMessageOut,
    ) -> Result<ApiClient, RegisterClientError> {
        let MlsMessageBodyOut::KeyPackage(key_package) = last_resort_key_package.body() else {
            return Err(RegisterClientError::InvalidInput(
                "MlsMessageOut is not a KeyPackage.",
            ));
        };
        let client_id = DsClientId::from_serialized_credential(
            key_package.leaf_node().credential().serialized_content(),
        )?;
        let request = RegisterClientRequestOut {
            key_packages,
            last_resort_key_package,
        };
        let message = MinimalDsMessageOut::RegisterClient(request);
        let ds_response = self.connection.send_message(message).await?;
        let auth_token = match ds_response {
            MinimalDsResponseIn::AuthToken(token) => token,
            _ => return Err(RegisterClientError::UnexpectedResponse),
        };
        Ok(ApiClient {
            connection: self.connection.clone(),
            auth_token,
            client_id,
            last_seen_message_sequence_number: 0,
        })
    }
}

/// An API client that is registered with the DS. It can be used to interact
/// with the DS through the methods provided.
pub struct ApiClient {
    connection: DsConnection,
    client_id: DsClientId,
    auth_token: AuthToken,
    last_seen_message_sequence_number: u64,
}

impl ApiClient {
    /// Upload the given key packages to the DS. Key packages are used by other
    /// clients to add this client to groups.
    pub async fn upload_key_packages(
        &mut self,
        key_packages: &[MlsMessageOut],
        last_resort_key_package: &MlsMessageOut,
    ) -> Result<(), UploadKeyPackagesError> {
        let request = requests::UploadKeyPackagesRequestOut {
            credentials: &self.client_credentials(),
            key_packages,
            last_resort_key_package,
        };
        let message = MinimalDsMessageOut::UploadKeyPackages(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Obtain a list of all clients registered with the DS.
    pub async fn list_clients(&self) -> Result<Vec<DsClientId>, ListClientsError> {
        let message = MinimalDsMessageOut::ListClients;
        let ds_response = self.connection.send_message(message).await?;
        let client_ids = match ds_response {
            MinimalDsResponseIn::ListClients(ids) => ids,
            _ => return Err(ListClientsError::UnexpectedResponse),
        };
        Ok(client_ids.into_iter().map(|id| id.into()).collect())
    }

    /// Create a new group on the DS with the given group info and ratchet tree.
    pub async fn create_group(
        &self,
        group_info: &MlsMessageOut,
        ratchet_tree: &RatchetTree,
    ) -> Result<(), CreateGroupError> {
        let request = requests::CreateGroupRequestOut {
            credentials: &self.client_credentials(),
            group_info,
            ratchet_tree,
        };
        let message = MinimalDsMessageOut::CreateGroup(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Fetch the key package for the client with the given [`DsClientId`] from the DS.
    pub async fn fetch_key_package(
        &self,
        client_id: DsClientId,
    ) -> Result<Option<KeyPackageIn>, FetchKeyPackageError> {
        let request = FetchKeyPackageRequest { client_id };
        let message = MinimalDsMessageOut::FetchKeyPackage(request);
        let ds_response = self.connection.send_message(message).await?;
        let key_package = match ds_response {
            MinimalDsResponseIn::KeyPackageOption(key_package_option) => key_package_option,
            _ => return Err(FetchKeyPackageError::UnexpectedResponse),
        };
        Ok(key_package)
    }

    /// Distribute a group message to all clients in a group. If the group
    /// message is a commit, `group_info_option` must be provided. `message`
    /// must be an [`MlsMessageOut`] with either a private or a public
    /// MLSMessage.
    pub async fn distribute_group_message(
        &self,
        message: &MlsMessageOut,
        group_info_option: Option<&MlsMessageOut>,
    ) -> Result<(), DistributeGroupMessageError> {
        let message = AssistedMessageOut::new(message.clone(), group_info_option.cloned())
            .map_err(|e| {
                let str = match e {
                    AssistedMessageError::InvalidMessage => "Unexpected MlsMessageBody.",
                    AssistedMessageError::MissingGroupInfo => "Missing GroupInfo.",
                };
                DistributeGroupMessageError::InvalidInput(str)
            })?;
        let request = requests::DistributeGroupMessageRequestOut {
            credentials: &self.client_credentials(),
            message: &message,
        };
        let message = MinimalDsMessageOut::DistributeGroupMessage(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Distribute a welcome message to all clients in a group. `message` must be
    /// a welcome message.
    pub async fn distribute_welcome(
        &self,
        message: &MlsMessageOut,
    ) -> Result<(), DistributeWelcomeError> {
        if !matches!(message.body(), MlsMessageBodyOut::Welcome(_)) {
            return Err(DistributeWelcomeError::InvalidInput(
                "MlsMessageOut is not a Welcome message.",
            ));
        }
        let request = requests::DistributeWelcomeRequestOut { message };
        let message = MinimalDsMessageOut::DistributeWelcome(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Fetch messages from the DS that were sent to this client.
    pub async fn fetch_messages(&mut self) -> Result<Vec<MlsMessageIn>, FetchMessagesError> {
        let request = FetchMessagesRequest {
            credentials: self.client_credentials(),
            last_seen_sequence_number: self.last_seen_message_sequence_number,
            number_of_messages: 100,
        };
        let message = MinimalDsMessageOut::FetchMessages(request);
        let ds_response = self.connection.send_message(message).await?;
        match ds_response {
            MinimalDsResponseIn::FetchMessages(response) => {
                self.last_seen_message_sequence_number = response
                    .messages
                    .last()
                    .map(|m| m.sequence_number)
                    .unwrap_or(0);
                let messages = response
                    .messages
                    .into_iter()
                    .map(|m| m.message.deserialize())
                    .collect::<Result<Vec<_>, tls_codec::Error>>()?;
                Ok(messages)
            }
            _ => Err(FetchMessagesError::UnexpectedResponse),
        }
    }

    /// Delete the group with the given [`DsGroupId`] from the DS.
    pub async fn delete_group(&self, group_id: DsGroupId) -> Result<(), DeleteGroupError> {
        let request = DeleteGroupRequest {
            credentials: self.client_credentials(),
            group_id: group_id,
        };
        let message = MinimalDsMessageOut::DeleteGroup(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Delete the client with the given [`DsClientId`] from the DS.
    pub async fn delete_client(&self, client_id: DsClientId) -> Result<(), DeleteClientError> {
        let request = DeleteClientRequest {
            credentials: self.client_credentials(),
            client_id,
        };
        let message = MinimalDsMessageOut::DeleteClient(request);
        self.connection.send_message(message).await?;
        Ok(())
    }

    /// Get the client ID of this client.
    pub fn client_id(&self) -> DsClientId {
        self.client_id.clone()
    }
}

// Helper functions
impl ApiClient {
    fn client_credentials(&self) -> ClientCredentials {
        ClientCredentials {
            client_id: self.client_id.clone(),
            token: self.auth_token,
        }
    }
}
