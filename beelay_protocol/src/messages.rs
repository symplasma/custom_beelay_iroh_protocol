use beelay_core::{OutboundRequestId, PeerId, StreamId};
use iroh::NodeId;
use serde::{Deserialize, Serialize};

/// Messages are used to send data over Iroh connections and reconcile Beelay commands that must be sent to other peers.
#[derive(Debug, Clone)]
pub enum Message {
    Request {
        source: PeerId,
        target: PeerId,
        senders_req_id: OutboundRequestId,
        request: Vec<u8>,
    },
    Response {
        source: PeerId,
        target: PeerId,
        id: OutboundRequestId,
        response: Vec<u8>,
    },
    Stream {
        source: PeerId,
        target: PeerId,
        stream_id_source: StreamId,
        stream_id_target: StreamId,
        msg: Vec<u8>,
    },
    StreamConnect {
        source: PeerId,
        target: PeerId,
        stream_id_source: StreamId,
        msg: Vec<u8>,
    },
    StreamAccept {
        source: PeerId,
        target: PeerId,
        stream_id_source: StreamId,
        stream_id_target: StreamId,
    },
    Done {
        source: PeerId,
    },
    Confirmation {
        target: PeerId,
    },
}

impl Message {
    pub fn target(&self) -> &PeerId {
        match self {
            Message::Request { target, .. } => target,
            Message::Response { target, .. } => target,
            Message::Stream { target, .. } => target,
            Message::StreamConnect { target, .. } => target,
            Message::StreamAccept { target, .. } => target,
            Message::Done { source: target } => target,
            Message::Confirmation { target } => target,
        }
    }

    pub fn target_node_id(&self) -> NodeId {
        let peer_id = self.target().as_bytes();
        NodeId::try_from(peer_id).expect("NodeId is invalid")
    }
}

/// This Message structure is used to translate non-serializable messages into serializable messages.
/// Some IDs do not implement the Serialize trait, so we need to convert them to bytes.
/// These are required internally to the Beelay structure, but must be sent across the wire,
/// requiring this new SerializableMessage structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableMessage {
    Request {
        source: Vec<u8>,
        target: Vec<u8>,
        senders_req_id: u64,
        request: Vec<u8>,
    },
    Response {
        source: Vec<u8>,
        target: Vec<u8>,
        id: u64,
        response: Vec<u8>,
    },
    Stream {
        source: Vec<u8>,
        target: Vec<u8>,
        stream_id_source: u64,
        stream_id_target: u64,
        msg: Vec<u8>,
    },
    StreamConnect {
        source: Vec<u8>,
        target: Vec<u8>,
        stream_id_source: u64,
        msg: Vec<u8>,
    },
    StreamAccept {
        source: Vec<u8>,
        target: Vec<u8>,
        stream_id_source: u64,
        stream_id_target: u64,
    },
    Done {
        source: Vec<u8>,
    },
    Confirmation {
        target: Vec<u8>,
    },
}

impl From<Message> for SerializableMessage {
    fn from(value: Message) -> Self {
        match value {
            Message::Request {
                source,
                target,
                senders_req_id,
                request,
            } => Self::Request {
                source: source.as_bytes().to_vec(),
                target: target.as_bytes().to_vec(),
                senders_req_id: senders_req_id.serialize(),
                request,
            },
            Message::Response {
                source,
                target,
                id,
                response,
            } => Self::Response {
                source: source.as_bytes().to_vec(),
                target: target.as_bytes().to_vec(),
                id: id.serialize(),
                response,
            },
            Message::Stream {
                source,
                target,
                stream_id_source,
                stream_id_target,
                msg,
            } => Self::Stream {
                source: source.as_bytes().to_vec(),
                target: target.as_bytes().to_vec(),
                stream_id_source: stream_id_source.serialize(),
                stream_id_target: stream_id_target.serialize(),
                msg,
            },
            Message::StreamConnect {
                source,
                target,
                stream_id_source,
                msg,
            } => Self::StreamConnect {
                source: source.as_bytes().to_vec(),
                target: target.as_bytes().to_vec(),
                stream_id_source: stream_id_source.serialize(),
                msg,
            },
            Message::StreamAccept {
                source,
                target,
                stream_id_source,
                stream_id_target,
            } => Self::StreamAccept {
                source: source.as_bytes().to_vec(),
                target: target.as_bytes().to_vec(),
                stream_id_source: stream_id_source.serialize(),
                stream_id_target: stream_id_target.serialize(),
            },
            Message::Done { source: target } => Self::Done {
                source: target.as_bytes().to_vec(),
            },
            Message::Confirmation { target } => Self::Confirmation {
                target: target.as_bytes().to_vec(),
            },
        }
    }
}

impl From<SerializableMessage> for Message {
    fn from(value: SerializableMessage) -> Self {
        match value {
            SerializableMessage::Request {
                source,
                target,
                senders_req_id,
                request,
            } => Self::Request {
                source: PeerId::try_from(source.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                senders_req_id: OutboundRequestId::from_serialized(senders_req_id),
                request,
            },
            SerializableMessage::Response {
                source,
                target,
                id,
                response,
            } => Self::Response {
                source: PeerId::try_from(source.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                id: OutboundRequestId::from_serialized(id),
                response,
            },
            SerializableMessage::Stream {
                source,
                target,
                stream_id_source,
                stream_id_target,
                msg,
            } => Self::Stream {
                source: PeerId::try_from(source.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                stream_id_source: StreamId::from_serialized(stream_id_source),
                stream_id_target: StreamId::from_serialized(stream_id_target),
                msg,
            },
            SerializableMessage::StreamConnect {
                source,
                target,
                stream_id_source,
                msg,
            } => Self::StreamConnect {
                source: PeerId::try_from(source.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                stream_id_source: StreamId::from_serialized(stream_id_source),
                msg,
            },
            SerializableMessage::StreamAccept {
                source,
                target,
                stream_id_source,
                stream_id_target,
            } => Self::StreamAccept {
                source: PeerId::try_from(source.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
                stream_id_source: StreamId::from_serialized(stream_id_source),
                stream_id_target: StreamId::from_serialized(stream_id_target),
            },
            SerializableMessage::Done { source: target } => Self::Done {
                source: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
            },
            SerializableMessage::Confirmation { target } => Self::Confirmation {
                target: PeerId::try_from(target.as_ref())
                    .expect("peer id should succeed unless corrupted"),
            },
        }
    }
}
