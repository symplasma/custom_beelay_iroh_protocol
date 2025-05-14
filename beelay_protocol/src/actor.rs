use std::fmt::Debug;
use tokio::sync::{mpsc, oneshot};
use beelay_core::{BundleSpec, Commit, CommitOrBundle, DocumentId, PeerId, StreamId};
use beelay_core::error::{AddCommits, CreateContactCard};
use beelay_core::keyhive::MemberAccess;
use ed25519_dalek::SigningKey;
use tokio::sync::mpsc::Sender;
use crate::beelay::BeelayBuilder;
use crate::messages::Message;
use crate::primitives::{ContactCardWrapper, KeyhiveEntityIdWrapper};
use crate::storage_handling::BeelayStorage;

#[derive(Debug)]
pub struct ActionResult<T: Debug> {
    messages: Vec<Message>,
    result: T,
}

impl<T: Debug> ActionResult<T> {
    pub(crate) fn new(result: T, messages: Vec<Message>) -> Self {
        Self { result, messages }
    }

    pub(crate) fn unpack(self) -> (T, Vec<Message>) {
        (self.result, self.messages)
    }
    fn result(&self) -> &T {
        &self.result
    }
    fn messages(&self) -> &Vec<Message> {
        &self.messages
    }
}

#[derive(Debug)]
pub(crate) enum BeelayAction {
    CreateDoc(
        oneshot::Sender<ActionResult<Result<(DocumentId, Commit), beelay_core::error::Create>>>,
        Vec<u8>,
        Vec<KeyhiveEntityIdWrapper>,
    ),
    LoadDoc(
        oneshot::Sender<ActionResult<Option<Vec<CommitOrBundle>>>>,
        DocumentId,
    ),
    DocStatus(
        oneshot::Sender<ActionResult<beelay_core::doc_status::DocStatus>>,
        DocumentId,
    ),
    AddCommits(
        oneshot::Sender<ActionResult<Result<Vec<BundleSpec>, AddCommits>>>,
        DocumentId,
        Vec<Commit>,
    ),
    CreateContactCard(oneshot::Sender<ActionResult<Result<ContactCardWrapper, CreateContactCard>>>),
    AddMemberToDoc(
        oneshot::Sender<ActionResult<()>>,
        DocumentId,
        KeyhiveEntityIdWrapper,
        MemberAccess,
    ),
    CreateStream(oneshot::Sender<ActionResult<StreamId>>, PeerId),
    AcceptStream(oneshot::Sender<ActionResult<StreamId>>, PeerId),
    DisconnectStream(oneshot::Sender<ActionResult<()>>, StreamId),
    SendMessage(oneshot::Sender<ActionResult<()>>, Message),
    DisplayStorage(oneshot::Sender<ActionResult<()>>),
}

#[derive(Debug)]
pub struct BeelayActor {
    nickname: String,
    signing_key: SigningKey,
    send_channel: Sender<BeelayAction>,
    beelay_sync_handle: std::thread::JoinHandle<()>,
}

impl BeelayActor {
    pub fn sigining_key(&self) -> &SigningKey {
        &self.signing_key
    }
    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.signing_key.verifying_key())
    }
    pub fn nickname(&self) -> &str {
        &self.nickname
    }
    pub fn send_channel(&self) -> Sender<BeelayAction> {
        self.send_channel.clone()
    }
    pub fn handle(&self) -> &std::thread::JoinHandle<()> {
        &self.beelay_sync_handle
    }
    pub async fn spawn(nickname: &str, signing_key: SigningKey, storage: BeelayStorage) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let beelay_tx = tx.clone();
        let signing_key_actor = signing_key.clone();
        let nickname_to_thread = nickname.to_string();

        // Spawn a dedicated thread with its own runtime for the BeelayWrapper
        let handler_thread = std::thread::spawn(move || {
            // Create a new runtime with a single-threaded scheduler
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            // Create a LocalSet to ensure all tasks stay on this thread
            let local = tokio::task::LocalSet::new();

            // Run the BeelayWrapper within the LocalSet
            rt.block_on(local.run_until(async move {
                // Create BeelayWrapper on this dedicated thread
                let mut wrapper = BeelayBuilder::new()
                    .nickname(nickname_to_thread)
                    .signing_key(signing_key)
                    .storage(storage)
                    .channel(tx, rx)
                    .build();

                // Process actions - this will run on this same thread
                wrapper.process_actions().await;
            }));
        });

        // Allow some time for the other thread to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Self {
            nickname: nickname.to_string(),
            signing_key: signing_key_actor,
            send_channel: beelay_tx,
            beelay_sync_handle: handler_thread,
        }
    }

    pub async fn display_storage(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send_channel
            .send(BeelayAction::DisplayStorage(sender))
            .await
            .unwrap();
        receiver.await.expect("Failed to print");
    }

    pub async fn create_doc(
        &self,
        content: Vec<u8>,
        other_owners: Vec<KeyhiveEntityIdWrapper>,
    ) -> ActionResult<Result<(DocumentId, Commit), beelay_core::error::Create>> {
        // Create the document action
        let (sender, receiver) = oneshot::channel();
        let beelay_create_doc = BeelayAction::CreateDoc(sender, content, other_owners);
        self.send_channel
            .send(beelay_create_doc)
            .await
            .expect("Failed to send create doc action");
        receiver.await.expect("Failed to receive create doc result")
    }

    pub async fn load_doc(&self, doc_id: DocumentId) -> ActionResult<Option<Vec<CommitOrBundle>>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_load_doc = BeelayAction::LoadDoc(sender, doc_id);
        self.send_channel
            .send(beelay_load_doc)
            .await
            .expect("Failed to send load doc action");
        receiver.await.expect("Failed to receive load doc result")
    }

    pub async fn doc_status(
        &self,
        document_id: DocumentId,
    ) -> ActionResult<beelay_core::doc_status::DocStatus> {
        let (sender, receiver) = oneshot::channel();
        let beelay_doc_status = BeelayAction::DocStatus(sender, document_id);
        self.send_channel
            .send(beelay_doc_status)
            .await
            .expect("Failed to send doc status action");
        receiver.await.expect("Failed to receive doc status result")
    }

    pub async fn add_commits(
        &self,
        document_id: DocumentId,
        commits: Vec<Commit>,
    ) -> ActionResult<Result<Vec<BundleSpec>, AddCommits>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_add_commits = BeelayAction::AddCommits(sender, document_id, commits);
        self.send_channel
            .send(beelay_add_commits)
            .await
            .expect("Failed to send add commits action");
        receiver
            .await
            .expect("Failed to receive add commits result")
    }

    pub async fn create_contact_card(
        &self,
    ) -> ActionResult<Result<ContactCardWrapper, CreateContactCard>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_create_contact_card = BeelayAction::CreateContactCard(sender);
        self.send_channel
            .send(beelay_create_contact_card)
            .await
            .expect("Failed to send create contact card action");
        receiver
            .await
            .expect("Failed to receive create contact card result")
    }

    pub async fn add_member_to_doc(
        &self,
        document_id: DocumentId,
        entity: KeyhiveEntityIdWrapper,
        access: MemberAccess,
    ) -> ActionResult<()> {
        let (sender, receiver) = oneshot::channel();
        let beelay_add_member_to_doc =
            BeelayAction::AddMemberToDoc(sender, document_id, entity, access);
        self.send_channel
            .send(beelay_add_member_to_doc)
            .await
            .expect("Failed to send add member to doc action");
        receiver
            .await
            .expect("Failed to receive add member to doc result")
    }

    pub async fn create_stream(&self, target: PeerId) -> ActionResult<StreamId> {
        let (sender, receiver) = oneshot::channel();
        let beelay_create_stream = BeelayAction::CreateStream(sender, target);
        self.send_channel
            .send(beelay_create_stream)
            .await
            .expect("Failed to send create stream action");
        receiver
            .await
            .expect("Failed to receive create stream result")
    }

    pub async fn accept_stream(&self, target: PeerId) -> ActionResult<StreamId> {
        let (sender, receiver) = oneshot::channel();
        let beelay_create_stream = BeelayAction::AcceptStream(sender, target);
        self.send_channel
            .send(beelay_create_stream)
            .await
            .expect("Failed to send accept stream action");
        receiver
            .await
            .expect("Failed to receive accept stream result")
    }

    pub async fn disconnect_stream(&self, stream_id: StreamId) -> ActionResult<()> {
        let (sender, receiver) = oneshot::channel();
        let beelay_disconnect_stream = BeelayAction::DisconnectStream(sender, stream_id);
        self.send_channel
            .send(beelay_disconnect_stream)
            .await
            .expect("Failed to send disconnect stream action");
        receiver
            .await
            .expect("Failed to receive disconnect stream result")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::pin::Pin;
    use beelay_core::{Commit, CommitHash};
    use beelay_core::keyhive::MemberAccess;
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;
    use tokio::sync::oneshot;
    use crate::actor::{BeelayAction, BeelayActor};
    use crate::messages::Message;
    use crate::primitives::KeyhiveEntityIdWrapper;

    async fn spawn_beelay_actor() -> BeelayActor {
        BeelayActor::spawn(
            "test",
            SigningKey::generate(&mut thread_rng()),
            BTreeMap::new(),
        )
        .await
    }

    #[tokio::test]
    async fn test_beelay_wrapper_create_doc() {
        // Create channels for the communicating with the beelay wrapper

        let beelay_actor = spawn_beelay_actor().await;

        // Create the document action
        let content = b"test content".to_vec();
        let other_owners = vec![];

        let (result, outgoing) = beelay_actor
            .create_doc(content.clone(), other_owners)
            .await
            .unpack();
        let (doc_id, commit) = result.expect("Failed to create document");

        // Do something with doc_id and commit...
        assert_eq!(commit.contents().to_vec(), content);
    }

    #[tokio::test]
    async fn test_beelay_actor_load_doc() {
        // Create a new BeelayActor
        let beelay_actor = spawn_beelay_actor().await;

        // First create a document to load
        let content = b"document to load".to_vec();
        let other_owners = vec![];

        let (result, outgoing) = beelay_actor
            .create_doc(content.clone(), other_owners)
            .await
            .unpack();
        let (doc_id, _) = result.expect("Failed to create document");

        // Now load the document
        let (loaded_doc, messages) = beelay_actor.load_doc(doc_id).await.unpack();

        // Verify the document was loaded correctly
        assert!(
            loaded_doc.is_some(),
            "Document should be loaded successfully"
        );

        // Check for the document content in the commits
        if let Some(commits) = loaded_doc {
            assert!(!commits.is_empty(), "Should have at least one commit");
            // Further verification could be done here depending on the structure
        }
    }

    #[tokio::test]
    async fn test_beelay_actor_add_commits() {
        // Create a new BeelayActor
        let beelay_actor = spawn_beelay_actor().await;

        // First create a document to modify
        let initial_content = b"initial content".to_vec();
        let other_owners = vec![];

        let (result, outgoing) = beelay_actor
            .create_doc(initial_content.clone(), other_owners)
            .await
            .unpack();
        let (doc_id, _) = result.expect("Failed to create document");

        // Create a new commit to add
        let new_content = b"updated content".to_vec();
        let hash = CommitHash::from(blake3::hash(&new_content).as_bytes());
        let commit = Commit::new(vec![], new_content, hash);

        // Add the commit to the document
        let (result, outgoing) = beelay_actor
            .add_commits(doc_id, vec![commit])
            .await
            .unpack();
        let result = result.expect("Failed to add commit");

        // Verify the document now has the new commit
        let (loaded_doc, messages) = beelay_actor.load_doc(doc_id).await.unpack();
        assert!(
            loaded_doc.is_some(),
            "Document should be loaded after adding commits"
        );
    }

    #[tokio::test]
    async fn test_beelay_actor_create_contact_card() {
        // Create a new BeelayActor
        let beelay_actor = spawn_beelay_actor().await;

        // Create a contact card
        let (contact_card, messages) = beelay_actor.create_contact_card().await.unpack();
        let contact_card = contact_card.expect("Failed to create contact card");

        // Verify the contact card was created successfully
        // We can't check the exact content but we can verify it exists
        assert!(contact_card.to_bytes().len() > 0, "Contact card should not be empty");
    }

    #[tokio::test]
    async fn test_beelay_actor_add_member_to_doc() {
        // Create a new BeelayActor
        let beelay_actor = spawn_beelay_actor().await;

        // First create a document
        let content = b"shared document".to_vec();
        let other_owners = vec![];

        let (result, outgoing) = beelay_actor
            .create_doc(content.clone(), other_owners)
            .await
            .unpack();
        let (doc_id, _) = result.expect("Failed to create document");

        // Create a contact card for a new member
        let (contact_card, messages) = beelay_actor.create_contact_card().await.unpack();
        let contact_card = contact_card.expect("Failed to create contact card");

        // Add the member to the document
        let entity = KeyhiveEntityIdWrapper::Individual(contact_card);
        let access = MemberAccess::Admin;

        // This doesn't return a result, but shouldn't panic
        beelay_actor.add_member_to_doc(doc_id, entity, access).await;

        // If we reach here without panicking, the test passes
        // Additional verification would require checking internal state
    }

    #[tokio::test]
    async fn test_beelay_actor_create_stream() {
        let actor = spawn_beelay_actor().await;
        let actor2 = spawn_beelay_actor().await;

        // Create a mock peer ID for testing
        let target_peer_id = actor2.peer_id();
        let source_peer_id = actor.peer_id();

        // Call the method under test
        let (stream_id, messages) = actor.create_stream(target_peer_id).await.unpack();
        assert!(!messages.is_empty());
        let stream_id2 = actor2.accept_stream(source_peer_id).await;
        assert!(!messages.is_empty());
    }

    #[tokio::test]
    async fn test_beelay_actor_disconnect_stream() {
        let actor = spawn_beelay_actor().await;
        let actor2 = spawn_beelay_actor().await;

        // Create a mock peer ID for testing
        let target_peer_id = actor2.peer_id();

        // First create a stream
        let (stream_id, messages) = actor.create_stream(target_peer_id).await.unpack();
        assert!(!messages.is_empty());

        // Then disconnect it
        // This should complete without error
        let (_, messages) = actor.disconnect_stream(stream_id).await.unpack();
        assert!(messages.is_empty());

        // Since disconnect_stream returns () (unit), we're just testing
        // that the function completes without panicking
    }

    fn process_actor_messages_between_2_actors<'a>(
        actor1: &'a BeelayActor,
        actor2: &'a BeelayActor,
        messages_to_2: Vec<Message>,
    ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        Box::pin(async move {
            for message in messages_to_2.into_iter() {
                println!("sending stream message to: {:?}", message.target());
                let (tx, rx) = oneshot::channel();
                let sendable_message = BeelayAction::SendMessage(tx, message);
                // println!("Sending message: {:?} {:?}", actor1.peer_id(), sendable_message);
                actor2.send_channel.send(sendable_message).await.unwrap();

                // wait for response
                let (_, messages_to_1) = rx.await.unwrap().unpack();
                process_actor_messages_between_2_actors(actor2, actor1, messages_to_1).await;
            }
        })
    }

    #[tokio::test]
    async fn test_beelay_document_sharing_and_streaming() {
        // 1. Spawn two separate beelay actors
        let actor1 = spawn_beelay_actor().await;
        let actor2 = spawn_beelay_actor().await;

        // 2. Create a document with a test entry on the first actor
        let test_content = b"test document content".to_vec();
        let (doc_result, _) = actor1.create_doc(test_content, vec![]).await.unpack();
        let (document_id, initial_commit) = doc_result.expect("Failed to create document");

        // 3. Create a contact card for the second actor
        let (contact_card_result, _) = actor2.create_contact_card().await.unpack();
        let contact_card = contact_card_result.expect("Failed to create contact card");

        // 4. Convert the contact card into a KeyhiveEntityIdWrapper of the Individual type
        let entity_id = KeyhiveEntityIdWrapper::Individual(contact_card);

        // 5. Add the second actor as a member to the document created on the first actor
        let (_, add_member_messages) = actor1
            .add_member_to_doc(document_id, entity_id, MemberAccess::Read)
            .await
            .unpack();

        // 6. Create a stream from the first actor to the second actor
        let target_peer_id = actor2.peer_id();
        let (stream_id, stream_messages) = actor1.create_stream(target_peer_id).await.unpack();

        // 7. Assert that there are outgoing messages from the stream creation
        assert!(
            !stream_messages.is_empty(),
            "Expected outgoing messages from stream creation"
        );
        process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;

        let (status, _) = actor2.doc_status(document_id).await.unpack();

        assert_eq!(
            status,
            beelay_core::doc_status::DocStatus {
                local_heads: Some(vec![initial_commit.hash()])
            }
        );

        println!("actor1: {:?}", actor1);
        actor1.display_storage().await;
        println!("-------------------------------------------------------------");
        println!("actor2: {:?}", actor2);
        actor2.display_storage().await;
    }
}