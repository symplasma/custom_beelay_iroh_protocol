use beelay_core::keyhive::KeyhiveEntityId;
use iroh::{NodeId, SecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::thread_rng;
use beelay_core::{CommandId, DocumentId, Event, OutboundRequestId, PeerId, StreamId};
use std::fmt::Debug;
use beelay_core::contact_card::ContactCard;

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

/// A wrapper for `beelay_core::Event` so that we can include additional context to process command results and build outgoing network messages.
pub enum EventData {
    Event(Event),
    RequestEvent(CommandId, Event, OutboundRequestId, PeerId),
    StreamEvent(StreamId, Event),
}

impl EventData {
    pub(crate) fn into_event(self) -> Event {
        match self {
            EventData::Event(event) => event,
            EventData::RequestEvent(command_id, event, _, _) => event,
            EventData::StreamEvent(stream_id, event) => event,
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct ContactCardWrapper(Vec<u8>);

impl ContactCardWrapper {
    pub(crate) fn to_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, beelay_core::error::Create> {
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
    pub(crate)fn set_target_stream_id(&mut self, target_stream_id: StreamId) {
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