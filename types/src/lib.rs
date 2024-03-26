// SPDX-FileCopyrightText: 2023 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::ops::Deref;

use openmls::{framing::MlsMessageIn, group::GroupId};
use thiserror::Error;
use tls_codec::{
    DeserializeBytes as TlsDeserializeBytesTrait, Serialize as TlsSerializeTrait, Size,
    TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};
use uuid::Uuid;

#[cfg(feature = "rusqlite")]
use rusqlite::{types::FromSql, ToSql};

pub mod requests;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TlsUuid {
    id: Uuid,
}

const UUID_LENGTH: usize = 16;

impl Size for TlsUuid {
    fn tls_serialized_len(&self) -> usize {
        UUID_LENGTH
    }
}

impl TlsSerializeTrait for TlsUuid {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = writer.write(self.id.as_bytes())?;
        Ok(written)
    }
}

impl TlsDeserializeBytesTrait for TlsUuid {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let id_bytes: [u8; UUID_LENGTH] = bytes
            .get(..UUID_LENGTH)
            .ok_or(tls_codec::Error::EndOfStream)?
            .try_into()?;
        let rest = bytes
            .get(UUID_LENGTH..)
            .ok_or(tls_codec::Error::EndOfStream)
            .unwrap();
        let id = Uuid::from_bytes(id_bytes);
        Ok((Self { id }, rest))
    }
}

impl From<Uuid> for TlsUuid {
    fn from(id: Uuid) -> Self {
        Self { id }
    }
}

impl Deref for TlsUuid {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    TlsSize,
    TlsSerialize,
    TlsDeserializeBytes,
)]
pub struct DsClientId {
    id: Vec<u8>,
}

impl DsClientId {
    pub fn new(bytes: &[u8]) -> Result<Self, DsClientIdError> {
        bytes.try_into()
    }

    pub fn from_serialized_credential(
        serialized_credential: &[u8],
    ) -> Result<Self, DsClientIdError> {
        // A BasicCredential only contains the identity, which in our case must
        // be a UUID.
        let identity = VLBytes::tls_deserialize_exact_bytes(serialized_credential)?;
        Self::try_from(identity.as_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.id
    }
}

impl std::fmt::Display for DsClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

#[derive(Debug, Error)]
pub enum DsClientIdError {
    #[error("Invalid Credential: {0}")]
    InvalidCredential(#[from] tls_codec::Error),
    #[error("Too many bytes in the input. Expected 32 bytes.")]
    TooManyBytes,
}

impl TryFrom<&[u8]> for DsClientId {
    type Error = DsClientIdError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() >= 1000 {
            return Err(DsClientIdError::TooManyBytes);
        }
        let id = bytes.to_vec();
        Ok(Self { id })
    }
}

#[cfg(feature = "rusqlite")]
impl ToSql for DsClientId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Borrowed(
            rusqlite::types::ValueRef::Blob(self.id.as_slice()),
        ))
    }
}

#[cfg(feature = "rusqlite")]
impl FromSql for DsClientId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let id = <Vec<u8>>::column_result(value)?;
        Ok(Self { id })
    }
}

#[cfg(feature = "rusqlite")]
impl ToSql for DsGroupId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.id.to_sql()
    }
}

#[cfg(feature = "rusqlite")]
impl FromSql for DsGroupId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let id = Uuid::column_result(value)?.into();
        Ok(DsGroupId { id })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct DsGroupId {
    id: TlsUuid,
}

impl From<DsGroupId> for GroupId {
    fn from(id: DsGroupId) -> Self {
        GroupId::from_slice(id.as_slice())
    }
}

impl TryFrom<GroupId> for DsGroupId {
    type Error = DsGroupIdError;

    fn try_from(id: GroupId) -> Result<Self, Self::Error> {
        let id = Uuid::from_slice(id.as_slice())?.into();
        Ok(Self { id })
    }
}

impl DsGroupId {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().into(),
        }
    }

    pub fn as_slice(&self) -> &[u8; 16] {
        self.id.as_bytes()
    }
}

#[derive(Debug, Error)]
pub enum DsGroupIdError {
    #[error(transparent)]
    InvalidUuid(#[from] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct AuthToken {
    token: [u8; 32],
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct ClientCredentials {
    pub client_id: DsClientId,
    pub token: AuthToken,
}

impl ClientCredentials {
    pub fn client_id(&self) -> DsClientId {
        self.client_id.clone()
    }
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct DsQueueMessage {
    message: Vec<u8>,
}

impl DsQueueMessage {
    pub fn as_slice(&self) -> &[u8] {
        &self.message
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { message: bytes }
    }

    pub fn deserialize(&self) -> Result<MlsMessageIn, tls_codec::Error> {
        MlsMessageIn::tls_deserialize_exact_bytes(self.as_slice())
    }
}

#[derive(Debug, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct NumberedDsQueueMessage {
    pub message: DsQueueMessage,
    pub sequence_number: u64,
}
