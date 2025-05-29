mod actor;
mod beelay;
mod messages;
mod primitives;
mod storage_handling;

use anyhow::Result;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, NodeAddr, endpoint::Connection, protocol::ProtocolHandler};
use n0_future::boxed::BoxFuture;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Application-Layer Protocol Negotiation (ALPN) identifier for the beelay protocol version 1.
pub const ALPN: &[u8] = b"beelay/1";

/// Main protocol handler for the Beelay network protocol implementation over IROH.
/// Manages connections, message handling, and protocol-specific operations.
#[derive(Debug, Clone)]
pub struct IrohBeelayProtocol {
    beelay_actor: Arc<actor::BeelayActor>,
    endpoint: Endpoint,
}

impl IrohBeelayProtocol {
    /// Creates a new instance of IrohBeelayProtocol.
    ///
    /// # Arguments
    /// * `iroh_beelay_id` - The unique identifier for this beelay node and iroh endpoint
    /// * `storage` - Storage implementation for persisting protocol data
    /// * `endpoint` - IROH network endpoint for communication
    pub async fn new(
        iroh_beelay_id: primitives::IrohBeelayID,
        storage: storage_handling::BeelayStorage,
        endpoint: Endpoint,
    ) -> Self {
        let beelay_actor = actor::BeelayActor::spawn(iroh_beelay_id.into(), storage).await;
        Self {
            beelay_actor: Arc::new(beelay_actor),
            endpoint,
        }
    }

    /// Returns a reference to the IROH endpoint used by this protocol instance.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns a reference to the BeelayActor that handles protocol logic.
    pub fn beelay_actor(&self) -> &Arc<actor::BeelayActor> {
        &self.beelay_actor
    }

    /// Establishes a connection to a remote node and sends and responds to batches of messages.
    ///
    /// # Arguments
    /// * `node_addr` - Address of the target node
    /// * `messages` - Vector of messages to be sent
    ///
    /// # Returns
    /// Result indicating success or failure of the operation
    pub async fn dial_node_and_send_messages(
        &self,
        node_addr: NodeAddr,
        messages: Vec<messages::Message>,
    ) -> Result<()> {
        let conn = self.endpoint.connect(node_addr, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        self.send_messages(messages, &mut send, &mut recv).await?;
        send.finish()?;
        conn.close(0u32.into(), b"bye!");
        Ok(())
    }

    // Iterator version of send_messages can be used to investigate
    // stack overflows on the recursive version if needed
    // async fn send_messages(
    //     &self,
    //     messages: Vec<messages::Message>,
    //     send: &mut SendStream,
    //     recv: &mut RecvStream,
    // ) -> Result<()> {
    //     let mut messages: VecDeque<messages::Message> = messages.into();
    //     while !messages.is_empty() {
    //         let msg = messages.pop_front().unwrap();
    //         Self::send_msg(msg, send).await?;
    //         loop {
    //             println!("in loop");
    //             let respond = Self::recv_msg(recv).await?;
    //             if let messages::Message::Done { .. } = respond {
    //                 println!("fround done!!");
    //                 break;
    //             };
    //             let (_, new_messages) = self.beelay_actor.incoming_message(respond).await.unpack();
    //             for m in new_messages.into_iter().rev() {
    //                 messages.push_front(m);
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    /// Sends multiple messages over a stream and handles their responses recursively.
    ///
    /// # Arguments
    /// * `messages` - Vector of messages to send
    /// * `send` - Stream for sending messages
    /// * `recv` - Stream for receiving responses
    ///
    /// # Returns
    /// Result indicating success or failure of sending all messages
    async fn send_messages(
        &self,
        messages: Vec<messages::Message>,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        for msg in messages {
            Self::send_msg(msg, send).await?;
            loop {
                let respond = Self::recv_msg(recv).await?;
                // we use Done to signal that we are done sending messages,
                // there are more efficient ways, but this is straightforward and works for now
                if let messages::Message::Done { .. } = respond {
                    break;
                };
                let (_, messages) = self.beelay_actor.incoming_message(respond).await.unpack();
                Box::pin(self.send_messages(messages, send, recv)).await?;
            }
        }
        Ok(())
    }

    /// Serializes and sends a single message over a stream, encoding the length of the 
    /// message alongside the message
    ///
    /// # Arguments
    /// * `msg` - Message to send
    /// * `send` - Stream for sending the message
    ///
    /// # Returns
    /// Result indicating success or failure of sending the message
    async fn send_msg(msg: messages::Message, send: &mut SendStream) -> Result<()> {
        let msg_serializable: messages::SerializableMessage = msg.into();
        let encoded = postcard::to_stdvec(&msg_serializable)?;
        send.write_all(&(encoded.len() as u64).to_le_bytes())
            .await?;
        send.write_all(&encoded).await?;
        Ok(())
    }

    /// Receives and deserializes a message from a stream.
    ///
    /// # Arguments
    /// * `recv` - Stream to receive message from
    ///
    /// # Returns
    /// Result containing the received message or an error
    async fn recv_msg(recv: &mut RecvStream) -> Result<messages::Message> {
        let mut incoming_len = [0u8; 8];
        recv.read_exact(&mut incoming_len).await?;
        let len = u64::from_le_bytes(incoming_len);

        let mut buffer = vec![0u8; len as usize];
        recv.read_exact(&mut buffer).await?;
        let msg: messages::SerializableMessage = postcard::from_bytes(&buffer)?;
        let msg_unserializable: messages::Message = msg.into();
        Ok(msg_unserializable)
    }
}

impl ProtocolHandler for IrohBeelayProtocol {
    /// Handles incoming connections by processing messages and routing responses.
    ///
    /// # Arguments
    /// * `connection` - The incoming connection to handle
    ///
    /// # Returns
    /// BoxFuture containing Result of connection handling
    fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
        let beelay_protocol = self.clone();
        let source_peer_id = beelay_protocol.beelay_actor.peer_id();
        Box::pin(async move {
            let node_id = connection.remote_node_id()?;
            println!("accepted connection from {node_id}");
            let (mut send, mut recv) = connection.accept_bi().await?;
            loop {
                // Read the message from the stream.
                match Self::recv_msg(&mut recv).await {
                    Ok(msg) => {
                        let (_, outgoing_messages) = beelay_protocol
                            .beelay_actor
                            .incoming_message(msg)
                            .await
                            .unpack();
                        let mut handles = Vec::new();
                        for (key, group) in outgoing_messages
                            .into_iter()
                            .fold(HashMap::new(), |mut acc, m| {
                                let target_node_id = m.target_node_id();
                                acc.entry(target_node_id).or_insert_with(Vec::new).push(m);
                                acc
                            })
                            .into_iter()
                        {
                            if key == node_id {
                                for msg in group {
                                    Self::send_msg(msg, &mut send).await?;
                                }
                            } else {
                                // send out to other nodes, create connections to do so
                                let new_beelay_protocol = beelay_protocol.clone();
                                let task = tokio::spawn(async move {
                                    new_beelay_protocol
                                        .dial_node_and_send_messages(key.into(), group)
                                        .await
                                });
                                handles.push(task);
                            }
                        }
                        // Send Done message so sender can terminate loop for this chunk of outgoing
                        Self::send_msg(
                            messages::Message::Done {
                                source: source_peer_id,
                            },
                            &mut send,
                        )
                        .await?;
                        for h in handles {
                            // not ideal for the time being, but this allows us to propagate up errors to the calling function
                            h.await??;
                        }
                    }
                    Err(e) => {
                        // In the case of an error, finish and close the connection, then return the error.
                        send.finish()?;
                        connection.closed().await;
                        Err(e)?;
                    }
                }
            }
            Ok(())
        })
    }
}

/// Initializes and starts a new Beelay node and IROH router.
///
/// Creates a new IrohBeelayID, sets up an IROH endpoint with discovery enabled,
/// initializes the protocol handler, and creates a router for handling incoming connections.
///
/// # Returns
/// A tuple containing the protocol router and protocol handler instance
pub async fn start_beelay_node() -> Result<(iroh::protocol::Router, IrohBeelayProtocol)> {
    let iroh_beelay_id = primitives::IrohBeelayID::generate();
    let endpoint = Endpoint::builder()
        .secret_key(iroh_beelay_id.clone().into())
        .discovery_n0()
        .bind()
        .await?;

    let beelay_protocal = IrohBeelayProtocol::new(
        iroh_beelay_id,
        storage_handling::BeelayStorage::new(),
        endpoint.clone(),
    )
    .await;
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(ALPN, beelay_protocal.clone()) // This makes the router handle incoming connections with our ALPN via Echo::accept!
        .spawn();

    Ok((router, beelay_protocal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::KeyhiveEntityIdWrapper;
    use beelay_core::keyhive::MemberAccess;
    use beelay_core::{Commit, CommitHash, CommitOrBundle};

    #[tokio::test]
    async fn it_works() {
        let (node_1, beelay_1) = start_beelay_node().await.unwrap();
        let (node_2, beelay_2) = start_beelay_node().await.unwrap();

        let test_content = Vec::new();
        let (doc_result, _) = beelay_1
            .beelay_actor()
            .create_doc(test_content, vec![])
            .await
            .unpack();
        let (document_id, initial_commit) = doc_result.expect("Failed to create document");

        // 3. Create a contact card for the second actor
        let (contact_card_result, _) = beelay_2.beelay_actor().create_contact_card().await.unpack();
        let contact_card = contact_card_result.expect("Failed to create contact card");

        // 4. Convert the contact card into a KeyhiveEntityIdWrapper of the Individual type
        let entity_id = KeyhiveEntityIdWrapper::Individual(contact_card);

        // 5. Add the second actor as a member to the document created on the first actor
        let (_, add_member_messages) = beelay_1
            .beelay_actor()
            .add_member_to_doc(document_id, entity_id, MemberAccess::Write)
            .await
            .unpack();

        // 6. Create a stream from the first actor to the second actor
        let target_peer_id = beelay_2.beelay_actor().peer_id();
        let (stream_id, stream_messages) = beelay_1
            .beelay_actor()
            .create_stream(target_peer_id)
            .await
            .unpack();

        // 7. Assert that there are outgoing messages from the stream creation
        assert!(
            !stream_messages.is_empty(),
            "Expected outgoing messages from stream creation"
        );

        let node_addr_2 = node_2.endpoint().node_addr().await.unwrap();
        beelay_1
            .dial_node_and_send_messages(node_addr_2, stream_messages)
            .await
            .unwrap();

        let (status, _) = beelay_2
            .beelay_actor()
            .doc_status(document_id)
            .await
            .unpack();

        assert_eq!(
            status,
            beelay_core::doc_status::DocStatus {
                local_heads: Some(vec![initial_commit.hash()])
            }
        );
        println!("{:?}", status);
        // FIXME: Initial commit is not sent to other nodes!!  this is a problem according
        //  to the beelay tests in the keyhive repo too.

        let actual_content = vec![1, 2, 3];
        let good_commit = Commit::new(
            vec![initial_commit.hash()],
            actual_content.clone(),
            CommitHash::from([1; 32]),
        );

        let (_, new_messages) = beelay_1
            .beelay_actor()
            .add_commits(document_id, vec![good_commit.clone()])
            .await
            .unpack();

        assert!(!new_messages.is_empty());

        let node_addr_2 = node_2.endpoint().node_addr().await.unwrap();
        beelay_1
            .dial_node_and_send_messages(node_addr_2, new_messages)
            .await
            .unwrap();

        let (commits_1, _) = beelay_1.beelay_actor().load_doc(document_id).await.unpack();

        let commit_filter = |commits: Option<Vec<CommitOrBundle>>| {
            commits
                .unwrap()
                .into_iter()
                .filter_map(|com| match com {
                    CommitOrBundle::Commit(c) => {
                        if c.hash() == good_commit.hash() {
                            Some(c)
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let commits_1 = commit_filter(commits_1);

        let (commits_2, _) = beelay_2.beelay_actor().load_doc(document_id).await.unpack();
        let commits_2 = commit_filter(commits_2);

        assert_eq!(commits_1, commits_2);

        // This makes sure the endpoint in the router is closed properly and connections close gracefully
        node_1.shutdown().await.unwrap();
        node_2.shutdown().await.unwrap();
    }
}
