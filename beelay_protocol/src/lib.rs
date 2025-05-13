mod beelay;

use anyhow::Result;
use iroh::{Endpoint, NodeAddr, endpoint::Connection, protocol::ProtocolHandler};
use n0_future::boxed::BoxFuture;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ALPN: &[u8] = b"beelay/1";

#[derive(Debug, Clone)]
pub struct IrohBeelayProtocol {
    beelay_actor: Arc<beelay::BeelayActor>,
}

impl IrohBeelayProtocol {
    fn new(beelay_actor: beelay::BeelayActor) -> Self {
        Self {
            beelay_actor: Arc::new(beelay_actor),
        }
    }
}

impl ProtocolHandler for IrohBeelayProtocol {
    fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
        Box::pin(async move {
            // We can get the remote's node id from the connection.
            let node_id = connection.remote_node_id()?;
            println!("accepted connection from {node_id}");

            // Our protocol is a simple request-response protocol, so we expect the
            // connecting peer to open a single bidirectional stream.
            let (mut send, mut recv) = connection.accept_bi().await?;

            // Echo any bytes received back directly.
            // This will keep copying until the sender signals the end of data on the stream.
            let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
            println!("Copied over {bytes_sent} byte(s)");

            // By calling `finish` on the send stream, we signal that we will not send anything
            // further, which makes the receive stream on the other end terminate.
            send.finish()?;

            // Wait until the remote closes the connection, which it does once it
            // received the response.
            connection.closed().await;

            Ok(())
        })
    }
}

pub async fn start_accept_side() -> Result<iroh::protocol::Router> {
    let iroh_beelay_id = beelay::IrohBeelayID::generate();
    let endpoint = Endpoint::builder()
        .secret_key(iroh_beelay_id.clone().into())
        .discovery_n0()
        .bind()
        .await?;
    let beelay_actor =
        beelay::BeelayActor::spawn("node", iroh_beelay_id.into(), BTreeMap::new()).await;

    let router = iroh::protocol::Router::builder(endpoint)
        .accept(ALPN, IrohBeelayProtocol::new(beelay_actor)) // This makes the router handle incoming connections with our ALPN via Echo::accept!
        .spawn()
        .await?;

    Ok(router)
}

pub async fn connect_side(addr: NodeAddr) -> Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Open a connection to the accepting node
    let conn = endpoint.connect(addr, ALPN).await?;

    // Open a bidirectional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await?;

    // Send some data to be echoed
    send.write_all(b"Hello, world!").await?;

    // Signal the end of data for this particular stream
    send.finish()?;

    // Receive the echo but limit reading up to a maximum of 1000 bytes
    let response = recv.read_to_end(1000).await?;
    assert_eq!(&response, b"Hello, world!");

    // Explicitly close the whole connection.
    conn.close(0u32.into(), b"bye!");

    // The above call only queues a close message to be sent (see how it's not async!).
    // We need to actually call this to make sure this message is sent out.
    endpoint.close().await;
    // If we don't call this but continue using the endpoint, we then the queued
    // close call will eventually be picked up and sent.
    // But always try to wait for endpoint.close().await to go through before dropping
    // the endpoint to ensure any queued messages are sent through and connections are
    // closed gracefully.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        let router = start_accept_side().await.unwrap();
        let node_addr = router.endpoint().node_addr().await.unwrap();

        connect_side(node_addr).await.unwrap();

        // This makes sure the endpoint in the router is closed properly and connections close gracefully
        router.shutdown().await.unwrap();
    }
}
