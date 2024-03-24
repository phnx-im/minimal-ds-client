// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use minimal_ds_types::DsClientIdError;
use openmls::prelude::tls_codec;
use reqwest::StatusCode;
use thiserror::Error;

/// Errors that can occur when sending a message to the DS.
#[derive(Error, Debug)]
pub enum SendMessageError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("Network error: {0}")]
    NetworkError(StatusCode),
    #[error("DS error: {0}")]
    MinimalDsError(String),
    #[error(transparent)]
    PayloadSerializationError(#[from] tls_codec::Error),
}

/// Errors that can occur when registering a client with the DS.
#[derive(Error, Debug)]
pub enum RegisterClientError {
    #[error("Invalid input : {0}")]
    InvalidInput(&'static str),
    #[error(transparent)]
    InvalidClientId(#[from] DsClientIdError),
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    RegisterClientError(#[from] SendMessageError),
}

/// Errors that can occur when requesting a list of clients from the DS.
#[derive(Error, Debug)]
pub enum ListClientsError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    RegisterClientError(#[from] SendMessageError),
}

/// Errors that can occur when fetching messages from the DS.
#[derive(Error, Debug)]
pub enum FetchMessagesError {
    #[error(transparent)]
    FetchMessagesError(#[from] SendMessageError),
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error("Error deserializing response: {0}")]
    DeserializationError(#[from] tls_codec::Error),
}

/// Errors that can occur when uploading key packages to the DS.
#[derive(Error, Debug)]
pub enum UploadKeyPackagesError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    UploadKeyPackageError(#[from] SendMessageError),
}

/// Errors that can occur when creating a group on the DS.
#[derive(Error, Debug)]
pub enum CreateGroupError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    CreateGroupError(#[from] SendMessageError),
}

/// Errors that can occur when fetching a key package from the DS.
#[derive(Error, Debug)]
pub enum FetchKeyPackageError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    FetchKeyPackageError(#[from] SendMessageError),
}

/// Errors that can occur when distributing a group message through the DS.
#[derive(Error, Debug)]
pub enum DistributeGroupMessageError {
    #[error("Invalid input : {0}")]
    InvalidInput(&'static str),
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    DistributeGroupMessageError(#[from] SendMessageError),
}

/// Errors that can occur when distributing a welcome message through the DS.
#[derive(Error, Debug)]
pub enum DistributeWelcomeError {
    #[error("Invalid input : {0}")]
    InvalidInput(&'static str),
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    DistributeWelcomeError(#[from] SendMessageError),
}

/// Errors that can occur when deleting a group on the DS.
#[derive(Error, Debug)]
pub enum DeleteGroupError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    DeleteGroupError(#[from] SendMessageError),
}

/// Errors that can occur when deleting a client from the DS.
#[derive(Error, Debug)]
pub enum DeleteClientError {
    #[error("Received an unexpected response.")]
    UnexpectedResponse,
    #[error(transparent)]
    DeleteClientError(#[from] SendMessageError),
}
