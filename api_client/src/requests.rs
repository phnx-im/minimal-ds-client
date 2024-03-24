// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use minimal_ds_types::{requests::FetchMessagesResponse, AuthToken, ClientCredentials, DsClientId};
use mls_assist::messages::AssistedMessageOut;
use openmls::{
    framing::MlsMessageOut,
    key_packages::KeyPackageIn,
    prelude::{tls_codec, TlsDeserializeBytes, TlsSerialize, TlsSize},
    treesync::RatchetTree,
};

// Re-exports
pub(super) use minimal_ds_types::requests::{
    DeleteClientRequest, DeleteGroupRequest, FetchKeyPackageRequest, FetchMessagesRequest,
};

#[derive(TlsSize, TlsDeserializeBytes)]
#[repr(u8)]
pub(super) enum MinimalDsResponseIn {
    Ok,
    AuthToken(AuthToken),
    KeyPackageOption(Option<KeyPackageIn>),
    FetchMessages(FetchMessagesResponse),
    ListClients(Vec<DsClientId>),
}

#[derive(TlsSize, TlsSerialize)]
#[repr(u8)]
pub(super) enum MinimalDsMessageOut<'a> {
    RegisterClient(RegisterClientRequestOut<'a>),
    UploadKeyPackages(UploadKeyPackagesRequestOut<'a>),
    ListClients,
    CreateGroup(CreateGroupRequestOut<'a>),
    FetchKeyPackage(FetchKeyPackageRequest),
    DistributeGroupMessage(DistributeGroupMessageRequestOut<'a>),
    DistributeWelcome(DistributeWelcomeRequestOut<'a>),
    FetchMessages(FetchMessagesRequest),
    DeleteGroup(DeleteGroupRequest),
    DeleteClient(DeleteClientRequest),
}

#[derive(TlsSize, TlsSerialize)]
pub(super) struct DistributeWelcomeRequestOut<'a> {
    pub(super) message: &'a MlsMessageOut,
}

#[derive(Debug, TlsSize, TlsSerialize)]
pub(super) struct DistributeGroupMessageRequestOut<'a> {
    pub(super) credentials: &'a ClientCredentials,
    pub(super) message: &'a AssistedMessageOut,
}

#[derive(TlsSize, TlsSerialize)]
pub(super) struct CreateGroupRequestOut<'a> {
    pub(super) credentials: &'a ClientCredentials,
    pub(super) group_info: &'a MlsMessageOut,
    pub(super) ratchet_tree: &'a RatchetTree,
}

#[derive(TlsSize, TlsSerialize)]
pub(super) struct UploadKeyPackagesRequestOut<'a> {
    pub(super) credentials: &'a ClientCredentials,
    pub(super) key_packages: &'a [MlsMessageOut],
    pub(super) last_resort_key_package: &'a MlsMessageOut,
}

#[derive(TlsSize, TlsSerialize)]
pub(super) struct RegisterClientRequestOut<'a> {
    pub(super) key_packages: &'a [MlsMessageOut],
    pub(super) last_resort_key_package: &'a MlsMessageOut,
}
