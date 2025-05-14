use beelay_core::{OutboundRequestId, PeerId, StreamId};

/// Messages are used to send data over Iroh connections and reconcile Beelay commands that must be sent to other peers.
#[derive(Debug)]
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
            Message::Confirmation { target } => target,
        }
    }
}