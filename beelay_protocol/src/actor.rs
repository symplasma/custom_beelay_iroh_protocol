use crate::beelay::BeelayBuilder;
use crate::messages::Message;
use crate::primitives::{AddMemberToGroupWrapper, ContactCardWrapper, KeyhiveEntityIdWrapper, RemoveMemberFromGroupWrapper};
use crate::storage_handling::BeelayStorage;
use beelay_core::error::{AddCommits, CreateContactCard, RemoveMember};
use beelay_core::keyhive::{KeyhiveEntityId, MemberAccess};
use beelay_core::{BundleSpec, Commit, CommitOrBundle, DocumentId, PeerId, StreamId};
use ed25519_dalek::SigningKey;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct ActionResult<T: Debug> {
    messages: Vec<Message>,
    result: T,
}

impl<T: Debug> ActionResult<T> {
    pub(crate) fn new(result: T, messages: VecDeque<Message>) -> Self {
        Self {
            result,
            messages: Vec::from(messages),
        }
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
pub enum BeelayAction {
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
    RemoveMemberFromDoc(
        oneshot::Sender<ActionResult<Result<(), beelay_core::error::RemoveMember>>>,
        DocumentId,
        KeyhiveEntityIdWrapper,
    ),
    CreateGroup(
        oneshot::Sender<ActionResult<Result<PeerId, beelay_core::error::CreateGroup>>>,
        Vec<KeyhiveEntityIdWrapper>,
    ),
    AddMemberToGroup(
        oneshot::Sender<ActionResult<Result<(), beelay_core::error::AddMember>>>,
        AddMemberToGroupWrapper,
    ),
    RemoveMemberFromGroup(
        oneshot::Sender<ActionResult<Result<(), beelay_core::error::RemoveMember>>>,
        RemoveMemberFromGroupWrapper,
    ),
    QueryAccess(
        oneshot::Sender<
            ActionResult<Result<HashMap<PeerId, MemberAccess>, beelay_core::error::QueryAccess>>,
        >,
        DocumentId,
    ),
    CreateStream(oneshot::Sender<ActionResult<StreamId>>, PeerId),
    AcceptStream(oneshot::Sender<ActionResult<StreamId>>, PeerId),
    DisconnectStream(oneshot::Sender<ActionResult<()>>, StreamId),
    SendMessage(oneshot::Sender<ActionResult<()>>, Message),
    DisplayValues(oneshot::Sender<ActionResult<()>>),
}

#[derive(Debug)]
pub struct BeelayActor {
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
    pub fn send_channel(&self) -> Sender<BeelayAction> {
        self.send_channel.clone()
    }
    pub fn handle(&self) -> &std::thread::JoinHandle<()> {
        &self.beelay_sync_handle
    }
    pub async fn spawn(signing_key: SigningKey, storage: BeelayStorage) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let beelay_tx = tx.clone();
        let signing_key_actor = signing_key.clone();

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
            signing_key: signing_key_actor,
            send_channel: beelay_tx,
            beelay_sync_handle: handler_thread,
        }
    }

    pub async fn incoming_message(&self, msg: Message) -> ActionResult<()> {
        let (sender, receiver) = oneshot::channel();
        self.send_channel
            .send(BeelayAction::SendMessage(sender, msg))
            .await
            .unwrap();
        receiver
            .await
            .expect("Failed to get response from sent message")
    }

    pub async fn display_storage(&self) {
        let (sender, receiver) = oneshot::channel();
        self.send_channel
            .send(BeelayAction::DisplayValues(sender))
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
    
    pub async fn remove_member_from_doc(
        &self,
        document_id: DocumentId,
        entity: KeyhiveEntityIdWrapper,
    ) -> ActionResult<Result<(), RemoveMember>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_remove_member_from_doc =
            BeelayAction::RemoveMemberFromDoc(sender, document_id, entity);
        self.send_channel
            .send(beelay_remove_member_from_doc)
            .await
            .expect("Failed to send remove member from doc action");
        receiver.await.expect("Failed to receive remove member from doc result")
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
    
    pub async fn create_group(&self, other_parents: Vec<KeyhiveEntityIdWrapper>) -> ActionResult<Result<PeerId, beelay_core::error::CreateGroup>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_create_group = BeelayAction::CreateGroup(sender, other_parents);
        self.send_channel
            .send(beelay_create_group)
            .await
            .expect("Failed to send create group action");
        receiver.await.expect("Failed to receive create group result")
    }
    
    pub async fn add_member_to_group(&self, add: AddMemberToGroupWrapper) -> ActionResult<Result<(), beelay_core::error::AddMember>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_add_member_to_group = BeelayAction::AddMemberToGroup(sender, add);
        self.send_channel
            .send(beelay_add_member_to_group)
            .await
            .expect("Failed to send add member to group action");
        receiver.await.expect("Failed to receive add member to group result")
    }
    
    pub async fn remove_member_from_group(&self, remove: RemoveMemberFromGroupWrapper) -> ActionResult<Result<(), beelay_core::error::RemoveMember>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_remove_member_from_group = BeelayAction::RemoveMemberFromGroup(sender, remove);
        self.send_channel
            .send(beelay_remove_member_from_group)
            .await
            .expect("Failed to send remove member from group action");
        receiver.await.expect("Failed to receive remove member from group result")
    }
    
    pub async fn query_access(&self, doc: DocumentId) -> ActionResult<Result<
        HashMap<PeerId, MemberAccess>,
        beelay_core::error::QueryAccess,
    >> {
        let (sender, receiver) = oneshot::channel();
        let beelay_query_access = BeelayAction::QueryAccess(sender, doc);
        self.send_channel
            .send(beelay_query_access)
            .await
            .expect("Failed to send query access action");
        receiver.await.expect("Failed to receive query access result")
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::{BeelayAction, BeelayActor};
    use crate::messages::Message;
    use crate::primitives::{AddMemberToGroupWrapper, KeyhiveEntityIdWrapper, RemoveMemberFromGroupWrapper};
    use beelay_core::keyhive::MemberAccess;
    use beelay_core::{Commit, CommitHash, CommitOrBundle};
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;
    use std::collections::{BTreeMap, VecDeque};
    use std::pin::Pin;
    use tokio::sync::oneshot;

    async fn spawn_beelay_actor() -> BeelayActor {
        BeelayActor::spawn(SigningKey::generate(&mut thread_rng()), BTreeMap::new()).await
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
        assert!(
            contact_card.to_bytes().len() > 0,
            "Contact card should not be empty"
        );
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

    // fn process_actor_messages_between_2_actors<'a>(
    //     actor1: &'a BeelayActor,
    //     actor2: &'a BeelayActor,
    //     messages_to_2: Vec<Message>,
    // ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    //     Box::pin(async move {
    //         for message in messages_to_2.into_iter() {
    //             let (tx, rx) = oneshot::channel();
    //             let sendable_message = BeelayAction::SendMessage(tx, message);
    //             // println!("Sending message: {:?} {:?}", actor1.peer_id(), sendable_message);
    //             actor2.send_channel.send(sendable_message).await.unwrap();
    // 
    //             // wait for response
    //             let (_, messages_to_1) = rx.await.unwrap().unpack();
    //             process_actor_messages_between_2_actors(actor2, actor1, messages_to_1).await;
    //         }
    //     })
    // }

    async fn process_actor_messages_between_2_actors<'a>(
        actor1: &'a BeelayActor,
        actor2: &'a BeelayActor,
        messages_to_2: Vec<Message>,
    ) {
        let mut message_queue = VecDeque::new();

        // Initialize the queue with the initial messages and actor pair
        for message in messages_to_2.into_iter() {
            message_queue.push_back((actor2, actor1, message));
        }

        while let Some((current_receiver, current_sender, message)) = message_queue.pop_front() {
            let (tx, rx) = oneshot::channel();
            let sendable_message = BeelayAction::SendMessage(tx, message);
            // println!("Sending message: {:?} {:?}", current_sender.peer_id(), sendable_message);
            current_receiver.send_channel.send(sendable_message).await.unwrap();

            // wait for response
            let (_, response_messages) = rx.await.unwrap().unpack();

            // Add response messages to the queue with swapped actors
            for response_message in response_messages.into_iter() {
                message_queue.push_back((current_sender, current_receiver, response_message));
            }
        }
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
    }

    #[tokio::test]
    async fn test_beelay_group_document_access_and_commits() {
        // 1. Create 2 beelay actors
        let actor1 = spawn_beelay_actor().await;
        let actor2 = spawn_beelay_actor().await;

        // 2. Create a group
        let (group_result, _) = actor1.create_group(vec![]).await.unpack();
        let group_id = group_result.expect("Failed to create group");

        // 3. Add both beelay actors to the group
        // First, create contact cards for both actors
        let (contact_card1_result, _) = actor1.create_contact_card().await.unpack();
        let contact_card1 = contact_card1_result.expect("Failed to create contact card for actor1");

        let (contact_card2_result, _) = actor2.create_contact_card().await.unpack();
        let contact_card2 = contact_card2_result.expect("Failed to create contact card for actor2");

        // Add actor1 to the group
        let add_member1 = AddMemberToGroupWrapper {
            group_id,
            member: KeyhiveEntityIdWrapper::Individual(contact_card1),
            access: MemberAccess::Admin,
        };
        let (add_result1, _) = actor1.add_member_to_group(add_member1).await.unpack();
        add_result1.expect("Failed to add actor1 to group");

        // Add actor2 to the group
        let add_member2 = AddMemberToGroupWrapper {
            group_id,
            member: KeyhiveEntityIdWrapper::Individual(contact_card2.clone()),
            access: MemberAccess::Admin,
        };
        let (add_result2, _) = actor1.add_member_to_group(add_member2).await.unpack();
        add_result2.expect("Failed to add actor2 to group");

        // set up stream to synchronize
        let target_peer_id = actor2.peer_id();
        let (stream_id, stream_messages) = actor1.create_stream(target_peer_id).await.unpack();

        // Set up communication between actors for syncing
        process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;
        
        println!("closing stream: {:?}", stream_id);

        let (_, stream_messages) = actor1.disconnect_stream(stream_id).await.unpack();
        process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;

        // 4. Create a document owned by this group
        let test_content = b"group document content".to_vec();
        let group_owners = vec![KeyhiveEntityIdWrapper::Group(group_id)];
        let (doc_result, _) = actor1.create_doc(test_content.clone(), group_owners).await.unpack();
        let (document_id, initial_commit) = doc_result.expect("Failed to create document");

        // 5. Query access for the document and validate that it is owned by the group
        let (access_result, _) = actor1.query_access(document_id).await.unpack();
        let access_map = access_result.expect("Failed to query access");

        // Verify that the group has access to the document
        assert!(access_map.contains_key(&group_id), "Group should have access to the document");
        assert!(access_map.contains_key(&actor2.peer_id()), "Actor 2 should have access to the document");
        assert!(access_map.contains_key(&actor1.peer_id()), "Actor 1 should have access to the document");

        // 6. Add a test commit
        let first_commit_content = b"first test commit".to_vec();
        let first_commit_hash = CommitHash::from(blake3::hash(&first_commit_content).as_bytes());
        let first_test_commit = Commit::new(
            vec![initial_commit.hash()],
            first_commit_content.clone(),
            first_commit_hash,
        );

        let (add_commits_result, _messages1) = actor1
            .add_commits(document_id, vec![first_test_commit.clone()])
            .await
            .unpack();
        add_commits_result.expect("Failed to add first test commit");
        
        // set up stream to synchronize
        let target_peer_id = actor2.peer_id();
        let (_, stream_messages) = actor1.create_stream(target_peer_id).await.unpack();

        // Set up communication between actors for syncing
        process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;

        // 7. Validate that the commit is present for both actors
        let (doc1_commits, _) = actor1.load_doc(document_id).await.unpack();
        let (doc2_commits, _) = actor2.load_doc(document_id).await.unpack();

        // Helper function to check if a commit exists in the document
        let contains_commit = |commits: Option<Vec<CommitOrBundle>>, target_hash: CommitHash| -> bool {
            if let Some(commits) = commits {
                commits.iter().any(|commit_or_bundle| {
                    if let CommitOrBundle::Commit(commit) = commit_or_bundle {
                        commit.hash() == target_hash
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        };

        assert!(
            contains_commit(doc1_commits, first_commit_hash),
            "First commit should be present in actor1's document"
        );
        assert!(
            contains_commit(doc2_commits, first_commit_hash),
            "First commit should be present in actor2's document"
        );

        // 8. Remove the second actor from the group
        let remove_member = RemoveMemberFromGroupWrapper {
            group_id,
            member: KeyhiveEntityIdWrapper::Individual(contact_card2),
        };
        let (remove_result, remove_messages) = actor1.remove_member_from_group(remove_member).await.unpack();
        remove_result.expect("Failed to remove actor2 from group");

        let (access_result, _) = actor1.query_access(document_id).await.unpack();
        let access_map = access_result.expect("Failed to query access");
        
        // validate that the user no longer has access to the document
        assert!(!access_map.contains_key(&actor2.peer_id()), "Actor 2 should have lost access to the document");
        assert!(access_map.contains_key(&actor1.peer_id()), "Actor 1 should retain access to the document");
        assert!(access_map.contains_key(&group_id), "Group should have access to the document");
        println!("access map: {:?}", access_map);
        
        println!("remove: {:?}", remove_messages);
        
        // set up stream to synchronize
        let target_peer_id = actor2.peer_id();
        let (_, stream_messages) = actor1.create_stream(target_peer_id).await.unpack();
        println!("stream messages: {:?}", stream_messages);

        //todo: cannot remove member from group, this is not tested in beelay tests and 
        // it causes infinite loop of streaming messages, confirmed that this occurs in the beelay tests as well
        // scenario: Alice creates a group, Alice and Bob are members of the group, Alice removes Bob from the group, Alice creates a stream with bob
        // the stream now runs for every, given the sizes of the messages, it appears to be a loop fo the same messages, or at least the same sizes
        
        // Process messages
        // process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;
        // 
        // println!("after process messages here I am!!!");
        // 
        // // 9. Make another test commit to the document
        // let second_commit_content = b"second test commit".to_vec();
        // let second_commit_hash = CommitHash::from(blake3::hash(&second_commit_content).as_bytes());
        // let second_test_commit = Commit::new(
        //     vec![first_commit_hash],
        //     second_commit_content.clone(),
        //     second_commit_hash,
        // );
        // 
        // let (add_commits_result2, _messages2) = actor1
        //     .add_commits(document_id, vec![second_test_commit.clone()])
        //     .await
        //     .unpack();
        // add_commits_result2.expect("Failed to add second test commit");
        // 
        // println!("here I am!!!");
        // 
        // // set up stream to synchronize
        // let target_peer_id = actor2.peer_id();
        // let (_, stream_messages) = actor1.create_stream(target_peer_id).await.unpack();
        // 
        // // Process messages (though actor2 should not receive them since it's removed from group)
        // process_actor_messages_between_2_actors(&actor1, &actor2, stream_messages).await;
        // 
        // // 10. Validate that the first commit is present in the document for the first actor but not the second
        // let (doc1_commits_final, _) = actor1.load_doc(document_id).await.unpack();
        // let (doc2_commits_final, _) = actor2.load_doc(document_id).await.unpack();
        // 
        // // Actor1 should have both commits
        // assert!(
        //     contains_commit(doc1_commits_final.clone(), first_commit_hash),
        //     "First commit should still be present in actor1's document"
        // );
        // assert!(
        //     contains_commit(doc1_commits_final, second_commit_hash),
        //     "Second commit should be present in actor1's document"
        // );
        // 
        // // Actor2 should only have the first commit (from before removal), not the second
        // assert!(
        //     contains_commit(doc2_commits_final.clone(), first_commit_hash),
        //     "First commit should still be present in actor2's document"
        // );
        // assert!(
        //     !contains_commit(doc2_commits_final, second_commit_hash),
        //     "Second commit should NOT be present in actor2's document after removal from group"
        // );
    }


}
