use beelay_core::contact_card::ContactCard;
use beelay_core::keyhive::{KeyhiveEntityId, MemberAccess};
use beelay_core::{DocumentId, PeerId, StreamId};
use ed25519_dalek::{SigningKey, VerifyingKey};
use iroh::{NodeId, SecretKey};
use rand::thread_rng;
use std::fmt::Debug;
use iroh_base::NodeAddr;
use iroh_base::ticket::{Error, NodeTicket, Ticket};
use serde::{Deserialize, Serialize};

/// A wrapper for `ed25519_dalek::SigningKey` that provides compatability with `iroh::NodeId` and `beelay_core::PeerId`.
/// Currently, this is used to merge identities for ease of use, but that will likely change and this will be used to generate separate IDs
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IrohBeelayID(SigningKey);

impl IrohBeelayID {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut thread_rng());
        Self(signing_key)
    }
    pub fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }

    pub fn key(&self) -> &SigningKey {
        &self.0
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl From<SigningKey> for IrohBeelayID {
    fn from(value: SigningKey) -> Self {
        Self(value)
    }
}

impl From<IrohBeelayID> for SigningKey {
    fn from(value: IrohBeelayID) -> Self {
        value.0
    }
}

impl From<IrohBeelayID> for SecretKey {
    fn from(value: IrohBeelayID) -> Self {
        SecretKey::from(value.0)
    }
}

impl From<IrohBeelayID> for NodeId {
    fn from(value: IrohBeelayID) -> Self {
        value.0.verifying_key().into()
    }
}

impl From<IrohBeelayID> for PeerId {
    fn from(value: IrohBeelayID) -> Self {
        value.0.verifying_key().into()
    }
}

/// NewType wrapper that is converts contact cards to bytes so that they can be Sendable
#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct ContactCardWrapper(Vec<u8>);

impl ContactCardWrapper {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, beelay_core::error::Create> {
        Ok(Self(bytes.to_vec()))
    }
}

impl From<ContactCard> for ContactCardWrapper {
    fn from(value: ContactCard) -> Self {
        Self(value.to_bytes())
    }
}

impl From<ContactCardWrapper> for ContactCard {
    fn from(value: ContactCardWrapper) -> Self {
        ContactCard::from_bytes(&value.0).unwrap()
    }
}

/// NewType wrapper that is converts KeyhiveEntityId to bytes so that they can be Sendable
#[derive(Debug, Clone, Hash)]
pub enum KeyhiveEntityIdWrapper {
    Individual(ContactCardWrapper),
    Group(PeerId),
    Doc(DocumentId),
    Public,
}

impl From<KeyhiveEntityIdWrapper> for KeyhiveEntityId {
    fn from(value: KeyhiveEntityIdWrapper) -> Self {
        match value {
            KeyhiveEntityIdWrapper::Individual(contact_card) => {
                KeyhiveEntityId::Individual(contact_card.into())
            }
            KeyhiveEntityIdWrapper::Group(peer_id) => KeyhiveEntityId::Group(peer_id.into()),
            KeyhiveEntityIdWrapper::Doc(doc_id) => KeyhiveEntityId::Doc(doc_id.into()),
            KeyhiveEntityIdWrapper::Public => KeyhiveEntityId::Public,
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct AddMemberToGroupWrapper {
    pub group_id: PeerId,
    pub member: KeyhiveEntityIdWrapper,
    pub access: MemberAccess,
}

impl From<AddMemberToGroupWrapper> for beelay_core::keyhive::AddMemberToGroup {
    fn from(value: AddMemberToGroupWrapper) -> Self {
        Self {
            group_id: value.group_id,
            member: value.member.into(),
            access: value.access,
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct RemoveMemberFromGroupWrapper {
    pub group_id: PeerId,
    pub member: KeyhiveEntityIdWrapper,
}

impl From<RemoveMemberFromGroupWrapper> for beelay_core::keyhive::RemoveMemberFromGroup {
    fn from(value: RemoveMemberFromGroupWrapper) -> Self {
        Self {
            group_id: value.group_id,
            member: value.member.into(),
        }
    }
}

#[derive(Debug)]
pub struct StreamState {
    target_peer_id: PeerId,
    source_stream_id: StreamId,
    target_stream_id: Option<StreamId>,
}

impl StreamState {
    pub(crate) fn connect(target_peer_id: PeerId, source_stream_id: StreamId) -> Self {
        Self {
            target_peer_id,
            source_stream_id,
            target_stream_id: None,
        }
    }
    pub(crate) fn set_target_stream_id(&mut self, target_stream_id: StreamId) {
        self.target_stream_id = Some(target_stream_id);
    }
    pub(crate) fn target_peer_id(&self) -> PeerId {
        self.target_peer_id
    }
    pub(crate) fn source_stream_id(&self) -> StreamId {
        self.source_stream_id
    }
    pub(crate) fn target_stream_id(&self) -> Option<StreamId> {
        self.target_stream_id
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeelayTicket {
    node_ticket: NodeTicket,
    beelay_contact: ContactCardWrapper,
}

impl BeelayTicket {
    pub fn new(node_ticket: NodeTicket, beelay_contact: ContactCardWrapper) -> Self {
        Self {
            node_ticket,
            beelay_contact,
        }
    }
    pub fn node_addr(&self) -> &NodeAddr {
        self.node_ticket.node_addr()
    }

    pub fn contact_card(&self) -> &ContactCardWrapper {
        &self.beelay_contact
    }
    
    pub fn into_components(self) -> (NodeTicket, ContactCardWrapper) {
        (self.node_ticket, self.beelay_contact)
    }
}

impl Ticket for BeelayTicket {
    const KIND: &'static str = "beelay";

    fn to_bytes(&self) -> Vec<u8> {
        let node_ticket_bytes = self.node_ticket.to_bytes();
        let mut buff = (node_ticket_bytes.len() as u64).to_be_bytes().to_vec();
        buff.extend_from_slice(&node_ticket_bytes);
        buff.extend_from_slice(self.beelay_contact.to_bytes());
        buff
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let len_bytes: [u8; 8] = bytes[0..8].try_into().map_err(|_| Error::Verify("invalid length"))?;
        let ticket_len = u64::from_be_bytes(len_bytes) as usize;

        // Extract the node ticket bytes
        let node_ticket_bytes = &bytes[8..8 + ticket_len];
        let node_ticket = NodeTicket::from_bytes(node_ticket_bytes)?;

        // Extract the remaining bytes for the beelay contact
        let contact_bytes = &bytes[8 + ticket_len..];
        let beelay_contact = ContactCardWrapper::from_bytes(contact_bytes)
            .map_err(|_| Error::Verify("invalid beelay contact"))?;

        Ok(Self {
            node_ticket,
            beelay_contact,
        })
    }
}