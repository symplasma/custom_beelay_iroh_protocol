mod actor;
mod beelay;
mod messages;
mod primitives;
mod storage_handling;

use anyhow::Result;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{endpoint::Connection, protocol::ProtocolHandler, Endpoint, NodeAddr};
use n0_future::boxed::BoxFuture;
use std::sync::Arc;

pub const ALPN: &[u8] = b"beelay/1";

#[derive(Debug, Clone)]
pub struct IrohBeelayProtocol {
    beelay_actor: Arc<actor::BeelayActor>,
    endpoint: Endpoint,
}

impl IrohBeelayProtocol {
    pub async fn new(
        nickname: &str,
        iroh_beelay_id: primitives::IrohBeelayID,
        storage: storage_handling::BeelayStorage,
        endpoint: Endpoint,
    ) -> Self {
        let beelay_actor =
            actor::BeelayActor::spawn(nickname, iroh_beelay_id.into(), storage).await;
        Self {
            beelay_actor: Arc::new(beelay_actor),
            endpoint,
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn beelay_actor(&self) -> &Arc<actor::BeelayActor> {
        &self.beelay_actor
    }

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

    async fn send_messages(
        &self,
        messages: Vec<messages::Message>,
        send: &mut SendStream,
        recv: &mut RecvStream,
    ) -> Result<()> {
        for msg in messages {
            Self::send_msg(msg, send).await?;
            let respond = Self::recv_msg(recv).await?;
            let (_, messages) = self.beelay_actor.incoming_message(respond).await.unpack();
            Box::pin(self.send_messages(messages, send, recv)).await?;
        }
        Ok(())
    }

    async fn send_msg(msg: messages::Message, send: &mut SendStream) -> Result<()> {
        let msg_serializable: messages::SerializableMessage = msg.into();
        let encoded = postcard::to_stdvec(&msg_serializable)?;
        send.write_all(&(encoded.len() as u64).to_le_bytes())
            .await?;
        send.write_all(&encoded).await?;
        Ok(())
    }

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
    fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
        let beelay_protocol = self.clone();
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
                        for msg in outgoing_messages {
                            //TODO: need to be able to dial out to other nodes if needed based on the target in the messages
                            Self::send_msg(msg, &mut send).await?;
                        }
                    }
                    Err(e) => {
                        // TODO: better error handling and ending of loop
                        send.finish()?;
                        connection.closed().await;
                        break;
                    }
                }
            }
            Ok(())
        })
    }
}

pub async fn start_beelay_node() -> Result<(iroh::protocol::Router, IrohBeelayProtocol)> {
    let iroh_beelay_id = primitives::IrohBeelayID::generate();
    let endpoint = Endpoint::builder()
        .secret_key(iroh_beelay_id.clone().into())
        .discovery_n0()
        .bind()
        .await?;

    let beelay_protocal = IrohBeelayProtocol::new(
        "node",
        iroh_beelay_id,
        storage_handling::BeelayStorage::new(),
        endpoint.clone(),
    )
    .await;
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(ALPN, beelay_protocal.clone()) // This makes the router handle incoming connections with our ALPN via Echo::accept!
        .spawn()
        .await?;

    Ok((router, beelay_protocal))
}

#[cfg(test)]
mod tests {
    use beelay_core::{Commit, CommitHash, CommitOrBundle};
    use super::*;
    use crate::primitives::KeyhiveEntityIdWrapper;
    use beelay_core::keyhive::MemberAccess;

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
        // FIXME: Initial commit is not sent to other nodes!!  this is a problem according to the beelay tests in the keyhive repo too.


        let actual_content = vec![1, 2, 3];
        let good_commit = Commit::new(vec![initial_commit.hash()], actual_content.clone(), CommitHash::from([1; 32]));

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

        let (commits_1, _) = beelay_1
            .beelay_actor()
            .load_doc(document_id)
            .await
            .unpack();
        let commits_1 = commits_1
            .unwrap()
            .into_iter()
            .filter_map(|com| {
                match com {
                    CommitOrBundle::Commit(c) => {
                        if c.hash() == good_commit.hash() {
                            Some(c)
                        } else {
                            None
                        }
                    },
                    _ => None,
                }
            }).collect::<Vec<_>>();
        
        let (commits_2, _) = beelay_2
            .beelay_actor()
            .load_doc(document_id)
            .await
            .unpack();
        let commits_2 = commits_2
            .unwrap()
            .into_iter()
            .filter_map(|com| {
                match com {
                    CommitOrBundle::Commit(c) => {
                        if c.hash() == good_commit.hash() {
                            Some(c)
                        } else {
                            None
                        }
                    },
                    _ => None,
                }
            }).collect::<Vec<_>>();
        
        assert_eq!(commits_1, commits_2);
        
        // This makes sure the endpoint in the router is closed properly and connections close gracefully
        node_1.shutdown().await.unwrap();
        node_2.shutdown().await.unwrap();
    }
}
