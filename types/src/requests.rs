// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tls_codec::{TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{ClientCredentials, DsClientId, DsGroupId, NumberedDsQueueMessage};

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct DeleteClientRequest {
    pub credentials: ClientCredentials,
    pub client_id: DsClientId,
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct DeleteGroupRequest {
    pub credentials: ClientCredentials,
    pub group_id: DsGroupId,
}

#[derive(TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct FetchKeyPackageRequest {
    pub client_id: DsClientId,
}

#[derive(TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct FetchMessagesRequest {
    pub credentials: ClientCredentials,
    pub last_seen_sequence_number: u64,
    pub number_of_messages: u32,
}

#[derive(TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct FetchMessagesResponse {
    pub messages: Vec<NumberedDsQueueMessage>,
}
