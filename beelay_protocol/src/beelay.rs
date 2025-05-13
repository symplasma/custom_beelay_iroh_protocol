use beelay_core::contact_card::ContactCard;
use beelay_core::error::{AddCommits, CreateContactCard};
use beelay_core::io::{IoAction, IoResult};
use beelay_core::keyhive::{KeyhiveCommandResult, KeyhiveEntityId, MemberAccess};
use beelay_core::{Beelay, BundleSpec, CommandId, CommandResult, Commit, CommitHash, CommitOrBundle, Config, DocumentId, Event, OutboundRequestId, PeerId, StreamId, UnixTimestampMillis, conn_info, StreamDirection};
use ed25519_dalek::{SigningKey, VerifyingKey};
use iroh::{NodeId, SecretKey};
use iroh::endpoint::{RecvStream, SendStream, Source};
use keyhive_core::crypto::verifiable::Verifiable;
use keyhive_core::principal::peer::Peer;
use n0_future::SinkExt;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use signature::SignerMut;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

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
    fn into_event(self) -> Event {
        match self {
            EventData::Event(event) => event,
            EventData::RequestEvent(command_id, event, _, _) => event,
            EventData::StreamEvent(stream_id, event) => event,
        }
    }
}

/// Messages are used to send data over Iroh connections and reconcile Beelay commands that must be sent to other peers.
#[derive(Debug)]
enum Message {
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
        stream_id_target: Option<StreamId>,
        msg: Vec<u8>,
    },
    Confirmation,
}

#[derive(Debug)]
enum BeelayAction {
    CreateDoc(
        oneshot::Sender<Result<(DocumentId, Commit), beelay_core::error::Create>>,
        Vec<u8>,
        Vec<KeyhiveEntityIdWrapper>,
    ),
    LoadDoc(oneshot::Sender<Option<Vec<CommitOrBundle>>>, DocumentId),
    DocStatus(
        oneshot::Sender<beelay_core::doc_status::DocStatus>,
        DocumentId,
    ),
    AddCommits(
        oneshot::Sender<Result<Vec<BundleSpec>, beelay_core::error::AddCommits>>,
        DocumentId,
        Vec<Commit>,
    ),
    CreateContactCard(
        oneshot::Sender<Result<ContactCardWrapper, beelay_core::error::CreateContactCard>>,
    ),
    AddMemberToDoc(
        oneshot::Sender<()>,
        DocumentId,
        KeyhiveEntityIdWrapper,
        MemberAccess,
    ),
    CreateStream(oneshot::Sender<StreamId>, PeerId),
    AcceptStream(oneshot::Sender<StreamId>, PeerId),
    DisconnectStream(oneshot::Sender<()>, StreamId),
    SendMessage(oneshot::Sender<Message>, Message),
}

#[derive(Debug, Clone, Hash)]
pub struct ContactCardWrapper(Vec<u8>);

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

/// function handles beelay tasks related to storage, currently implemented only for Btree, but will be implemented for proper CRDT storage in the future
fn handle_task(
    storage: &mut BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    signing_key: &mut SigningKey,
    task: beelay_core::io::IoTask,
) -> IoResult {
    let id = task.id();
    match task.take_action() {
        IoAction::Load { key } => {
            let data = storage.get(&key).cloned();
            IoResult::load(id, data)
        }
        IoAction::Put { key, data } => {
            storage.insert(key, data);
            IoResult::put(id)
        }
        IoAction::Delete { key } => {
            storage.remove(&key);
            IoResult::delete(id)
        }
        IoAction::LoadRange { prefix } => {
            let results = storage
                .iter()
                .filter_map(|(k, v)| {
                    if prefix.is_prefix_of(k) {
                        Some((k.clone(), v.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            IoResult::load_range(id, results)
        }
        IoAction::ListOneLevel { prefix } => {
            let keys_in_storage = storage.keys().map(|k| k.to_string()).collect::<Vec<_>>();
            tracing::trace!(prefix = ?prefix, ?keys_in_storage, "listing one level of storage");
            let results = storage
                .keys()
                .filter_map(|k| k.onelevel_deeper(&prefix))
                .collect();
            IoResult::list_one_level(id, results)
        }
        IoAction::Sign { payload } => {
            let signature = signing_key.sign(&payload);
            IoResult::sign(id, signature)
        }
    }
}

#[derive(Debug)]
pub struct BeelayActor {
    nickname: String,
    signing_key: SigningKey,
    send_channel: Sender<BeelayAction>,
    handle: std::thread::JoinHandle<()>,
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
        &self.handle
    }
    pub async fn spawn(
        nickname: &str,
        signing_key: SigningKey,
        storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    ) -> Self {
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
            handle: handler_thread,
        }
    }

    pub async fn create_doc(
        &self,
        content: Vec<u8>,
        other_owners: Vec<KeyhiveEntityIdWrapper>,
    ) -> Result<(DocumentId, Commit), beelay_core::error::Create> {
        // Create the document action
        let (sender, receiver) = oneshot::channel();
        let beelay_create_doc = BeelayAction::CreateDoc(sender, content, other_owners);
        self.send_channel
            .send(beelay_create_doc)
            .await
            .expect("Failed to send create doc action");
        receiver.await.expect("Failed to receive create doc result")
    }

    pub async fn load_doc(&self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let (sender, receiver) = oneshot::channel();
        let beelay_load_doc = BeelayAction::LoadDoc(sender, doc_id);
        self.send_channel
            .send(beelay_load_doc)
            .await
            .expect("Failed to send load doc action");
        receiver.await.expect("Failed to receive load doc result")
    }

    pub async fn add_commits(
        &self,
        document_id: DocumentId,
        commits: Vec<Commit>,
    ) -> Result<Vec<BundleSpec>, AddCommits> {
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

    pub async fn create_contact_card(&self) -> Result<ContactCardWrapper, CreateContactCard> {
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
    ) {
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

    pub async fn create_stream(&self, target: PeerId) -> StreamId {
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

    pub async fn accept_stream(&self, target: PeerId) -> StreamId {
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

    pub async fn disconnect_stream(&self, stream_id: StreamId) {
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

/// This is the main entry point for building a Beelay state machine and ensuring it is either properly loaded from storage or built from scratch.
struct BeelayBuilder {
    nickname: Option<String>,
    signing_key: Option<SigningKey>,
    storage: Option<BTreeMap<beelay_core::StorageKey, Vec<u8>>>,
    recv_channel: Option<Receiver<BeelayAction>>,
    send_channel: Option<Sender<BeelayAction>>,
}

impl BeelayBuilder {
    pub fn new() -> Self {
        Self {
            nickname: None,
            signing_key: None,
            storage: None,
            recv_channel: None,
            send_channel: None,
        }
    }

    pub fn nickname(mut self, nickname: String) -> Self {
        self.nickname = Some(nickname);
        self
    }

    pub fn signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    pub fn storage(mut self, storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn channel(
        mut self,
        sender: Sender<BeelayAction>,
        receiver: Receiver<BeelayAction>,
    ) -> Self {
        self.recv_channel = Some(receiver);
        self.send_channel = Some(sender);
        self
    }

    fn build(self) -> BeelayWrapper<ThreadRng> {
        let mut storage = match self.storage {
            Some(storage) => {
                if self.signing_key.is_none() {
                    // TODO: turn this into a proper error
                    panic!("signing key must be provided when loading from storage");
                }
                storage
            }
            None => BTreeMap::new(),
        };
        let mut signing_key = self
            .signing_key
            .unwrap_or_else(|| SigningKey::generate(&mut thread_rng()));
        let nickname = self.nickname.unwrap_or_else(|| {
            let verifying_key = signing_key.verifying_key();
            hex::encode(verifying_key.as_bytes())
        });

        let (recv_channel, send_channel) = if let (Some(recv_channel), Some(send_channel)) =
            (self.recv_channel, self.send_channel)
        {
            (recv_channel, send_channel)
        } else {
            let (sender, receiver) = mpsc::channel(100);
            (receiver, sender)
        };

        let config = Config::new(thread_rng(), signing_key.verifying_key());
        let mut step = beelay_core::Beelay::load(config, UnixTimestampMillis::now());
        let mut completed_tasks = Vec::new();
        let mut inbox = VecDeque::new();
        let beelay = loop {
            match step {
                beelay_core::loading::Step::Loading(loading, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        completed_tasks.push(result);
                    }
                    if let Some(task_result) = completed_tasks.pop() {
                        step = loading.handle_io_complete(UnixTimestampMillis::now(), task_result);
                        continue;
                    } else {
                        panic!("no tasks completed but still loading");
                    }
                }
                beelay_core::loading::Step::Loaded(beelay, io_tasks) => {
                    for task in io_tasks {
                        let result = handle_task(&mut storage, &mut signing_key, task);
                        completed_tasks.push(result);
                    }
                    break beelay;
                }
            }
        };
        for result in completed_tasks {
            inbox.push_back(EventData::Event(Event::io_complete(result)));
        }
        let beelay_wrapper = BeelayWrapper::generate_primed_beelay(
            signing_key,
            &*nickname,
            beelay,
            storage,
            inbox,
            recv_channel,
            send_channel,
        );
        beelay_wrapper
    }
}

struct Connection {
    send: SendStream,
    recv: RecvStream,
}

// TODO: we should send messages to an actor to handle Beelay state management and connections
//  instead of locking, this will limit the need for both locks

pub struct BeelayWrapper<R: rand::Rng + rand::CryptoRng> {
    nickname: String,
    signing_key: SigningKey,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: Beelay<R>,

    outbox: Vec<Message>,
    inbox: VecDeque<EventData>,

    completed_commands: HashMap<CommandId, Result<CommandResult, beelay_core::error::Stopping>>,

    notifications: HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>>,
    peer_changes: HashMap<PeerId, Vec<conn_info::ConnectionInfo>>,

    handling_requests: HashMap<CommandId, (OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, PeerId>,

    shutdown: bool,

    streams: HashMap<StreamId, PeerId>,
    starting_streams: HashMap<CommandId, PeerId>,

    recv_channel: Receiver<BeelayAction>,
    send_channel: Sender<BeelayAction>,
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> BeelayWrapper<R> {
    fn generate_primed_beelay(
        signing_key: SigningKey,
        nickname: &str,
        core: Beelay<R>,
        storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
        inbox: VecDeque<EventData>,
        recv_channel: Receiver<BeelayAction>,
        send_channel: Sender<BeelayAction>,
    ) -> BeelayWrapper<R> {
        let mut beelay_wrapper = Self {
            nickname: nickname.to_string(),
            signing_key,
            storage,
            core,
            outbox: Vec::new(),
            inbox,
            completed_commands: HashMap::new(),
            notifications: HashMap::new(),
            peer_changes: HashMap::new(),
            handling_requests: HashMap::new(),
            endpoints: HashMap::new(),
            shutdown: false,
            streams: HashMap::new(),
            starting_streams: HashMap::new(),
            recv_channel,
            send_channel,
        };

        beelay_wrapper.handle_events();
        beelay_wrapper
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.signing_key.verifying_key())
    }

    pub fn handle_events(&mut self) {
        if self.shutdown {
            return;
        }
        while let Some(event) = self.inbox.pop_front() {
            let event = event.into_event();
            let now = UnixTimestampMillis::now();
            let results = {
                self.core
                    .handle_event(now, event)
                    .expect("the stop should be controlled")
            };
            for task in results.new_tasks.into_iter() {
                let event = self.handle_task(task);
                self.inbox.push_back(EventData::Event(event));
            }

            for (command, result) in results.completed_commands.into_iter() {
                if let Ok(CommandResult::CreateStream(stream_id)) = result {
                    let target = self
                        .starting_streams
                        .remove(&command)
                        .expect("should be a starting stream registered");
                    self.streams.insert(stream_id, target);
                }
                if let Ok(CommandResult::HandleRequest(response)) = &result {
                    let Ok(response) = response else {
                        continue;
                    };
                    if let Some((sender_req_id, sender)) = self.handling_requests.remove(&command) {
                        self.outbox.push(Message::Response {
                            source: self.peer_id(),
                            target: sender,
                            id: sender_req_id,
                            response: response.encode(),
                        });
                    }
                }
                self.completed_commands.insert(command, result);
            }
            for (target, msgs) in results.new_requests {
                let peer_id = self.endpoints.get(&target).expect("endpoint doesn't exist");
                for msg in msgs {
                    self.outbox.push(Message::Request {
                        source: self.peer_id(),
                        target: *peer_id,
                        senders_req_id: msg.id,
                        request: msg.request.encode(),
                    })
                }
            }
            for (id, events) in results.new_stream_events {
                for event in events {
                    tracing::trace!(?event, "stream event");
                    let target = self.streams.get(&id).unwrap();
                    match event {
                        beelay_core::StreamEvent::Send(msg) => self.outbox.push(Message::Stream {
                            source: self.peer_id(),
                            target: *target,
                            stream_id_source: id,
                            stream_id_target: None,
                            msg,
                        }),
                        beelay_core::StreamEvent::Close => {
                            self.streams.remove(&id);
                        }
                    }
                }
            }
            for (doc_id, events) in results.notifications.into_iter() {
                self.notifications.entry(doc_id).or_default().extend(events);
            }
            for (peer_id, status) in results.peer_status_changes.into_iter() {
                self.peer_changes.entry(peer_id).or_default().push(status);
            }
            if results.stopped {
                self.shutdown = true;
            }
        }
        println!("outbox: {:?}", self.outbox);
    }

    pub fn handle_task(&mut self, task: beelay_core::io::IoTask) -> Event {
        let result = handle_task(&mut self.storage, &mut self.signing_key, task);
        Event::io_complete(result)
    }

    pub fn pop_notifications(
        &mut self,
    ) -> HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>> {
        std::mem::take(&mut self.notifications)
    }

    pub fn create_doc_with_contents(
        &mut self,
        content: Vec<u8>,
        other_owners: Vec<KeyhiveEntityId>,
    ) -> Result<(DocumentId, beelay_core::Commit), beelay_core::error::Create> {
        let hash = CommitHash::from(blake3::hash(&content).as_bytes());
        let initial_commit = beelay_core::Commit::new(vec![], content, hash);
        let command = {
            let (command, event) = Event::create_doc(initial_commit.clone(), other_owners);
            self.inbox.push_back(EventData::Event(event));
            self.handle_events();
            command
        };

        // Doc is created at this point with io tasks handled.  We now have some events to deal with
        // across the network that may yield additional events to complete
        // this action in its entirety.

        self.handle_events();

        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::CreateDoc(doc_id))) => {
                let doc_id = doc_id?;
                Ok((doc_id, initial_commit))
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn load_doc(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let command = {
            let (command, event) = Event::load_doc(doc_id);
            self.inbox.push_back(EventData::Event(event));
            command
        };
        self.handle_events();
        match self.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn contact_card(&mut self) -> Result<ContactCard, beelay_core::error::CreateContactCard> {
        let (command_id, event) = Event::create_contact_card();
        self.inbox.push_back(EventData::Event(event));
        self.handle_events();

        match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(KeyhiveCommandResult::CreateContactCard(r)))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn add_member_to_doc(
        &mut self,
        doc: DocumentId,
        member: KeyhiveEntityId,
        access: MemberAccess,
    ) {
        let (command_id, event) = Event::add_member_to_doc(doc, member, access);
        self.inbox.push_back(EventData::Event(event));
        self.handle_events();
        match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(KeyhiveCommandResult::AddMemberToDoc))) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn create_stream(
        &mut self,
        target: &PeerId,
        direction: beelay_core::StreamDirection,
    ) -> StreamId {
        let (command, event) = Event::create_stream(direction);
        self.starting_streams.insert(command, *target);
        self.inbox.push_back(EventData::Event(event));
        self.handle_events();
        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::CreateStream(stream_id))) => stream_id,
            Some(other) => panic!(
                "unexpected command result when creating stream: {:?}",
                other
            ),
            None => panic!("no command result when creating stream"),
        }
    }

    pub fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<beelay_core::Commit>,
    ) -> Result<Vec<BundleSpec>, beelay_core::error::AddCommits> {
        let command = {
            let (command, event) = Event::add_commits(doc_id, commits);
            self.inbox.push_back(EventData::Event(event));
            command
        };
        self.handle_events();
        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::AddCommits(new_bundles_needed))) => new_bundles_needed,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn doc_status(&mut self, doc: &DocumentId) -> beelay_core::doc_status::DocStatus {
        let command = {
            let (command, event) = Event::query_status(*doc);
            self.inbox.push_back(EventData::Event(event));
            command
        };
        self.handle_events();

        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::QueryStatus(status))) => status,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn disconnect(&mut self, stream: StreamId) {
        let (command_id, event) = Event::disconnect_stream(stream);
        self.inbox.push_back(EventData::Event(event));

        self.handle_events();

        match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::DisconnectStream)) => {}
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
    }

    pub fn register_endpoint(&mut self, other: &PeerId) -> beelay_core::EndpointId {
        let command = {
            let (command, event) = Event::register_endpoint(beelay_core::Audience::peer(other));
            self.inbox.push_back(EventData::Event(event));
            command
        };
        self.handle_events();
        let endpoint_id = match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::RegisterEndpoint(endpoint_id))) => endpoint_id,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        self.endpoints.insert(endpoint_id, *other);
        endpoint_id
    }

    pub async fn process_actions(&mut self) {
        while let Some(action) = self.recv_channel.recv().await {
            match action {
                BeelayAction::CreateDoc(reply, content, other_owners) => {
                    let other_owners = other_owners.into_iter().map(|x| x.into()).collect();
                    let result = self.create_doc_with_contents(content, other_owners);
                    reply.send(result).expect("send failed create doc")
                }
                BeelayAction::LoadDoc(reply, doc_id) => {
                    let result = self.load_doc(doc_id);
                    reply.send(result).expect("send failed load doc")
                }
                BeelayAction::DocStatus(reply, doc_id) => {
                    let result = self.doc_status(&doc_id);
                    reply.send(result).expect("send failed doc status")
                }
                BeelayAction::AddCommits(reply, doc_id, commits) => {
                    let result = self.add_commits(doc_id, commits);
                    reply.send(result).expect("send failed add commits")
                }
                BeelayAction::CreateContactCard(reply) => {
                    let result = match self.contact_card() {
                        Ok(contact_card) => Ok(contact_card.into()),
                        Err(e) => Err(e),
                    };
                    reply.send(result).expect("send failed create contact card")
                }
                BeelayAction::AddMemberToDoc(reply, doc_id, member, access) => {
                    let result = self.add_member_to_doc(doc_id, member.into(), access);
                    reply.send(result).expect("send failed add member to doc")
                }
                BeelayAction::CreateStream(reply, target) => {
                    let result = self.create_stream(&target, StreamDirection::Connecting {remote_audience: beelay_core::Audience::peer(&target)});
                    reply.send(result).expect("send failed create stream")
                }
                BeelayAction::AcceptStream(reply, target) => {
                    let result = self.create_stream(&target, StreamDirection::Accepting {receive_audience: None});
                    reply.send(result).expect("send failed create stream")
                }
                BeelayAction::DisconnectStream(reply, stream_id) => {
                    let result = self.disconnect(stream_id);
                    reply.send(result).expect("send failed disconnect stream")
                }
                BeelayAction::SendMessage(_, _) => {
                    break;
                }
            }
            // TODO: output network events to the controller
        }
    }

    pub fn run_until_quiescent(&mut self) {
        loop {
            self.handle_events();
            if self.outbox.is_empty() {
                // no actions to take on the network
                break;
            }
            let sender = self.peer_id();
            let outbox = std::mem::take(&mut self.outbox);
            // All messages in the outbox must be processed into an event we can send
            // across the network.
            // We want to decouple the receiving of any responses from the network into an active
            // listening task that can inject them back into this state machine and respond to
            // whatever the original command was
            for msg in outbox.into_iter() {
                match msg {
                    Message::Request {
                        source,
                        target,
                        senders_req_id,
                        request,
                    } => {
                        let signed_message = beelay_core::SignedMessage::decode(&request).unwrap();
                        let (command_id, event) = Event::handle_request(signed_message, None);
                        // TODO: send this event over to target peer
                        let event_data =
                            EventData::RequestEvent(command_id, event, senders_req_id, sender);
                        // connection.send should receive this event, command_id, sender, request_id
                    }
                    Message::Response {
                        source,
                        target,
                        id,
                        response,
                    } => {
                        let response = beelay_core::EndpointResponse::decode(&response).unwrap();
                        let (_command_id, event) = Event::handle_response(id, response);
                        //TODO: send this event ot target peer
                        let event_data = EventData::Event(event);
                        // connection.send should receive this event
                    }
                    Message::Stream {
                        source,
                        target,
                        stream_id_source,
                        stream_id_target,
                        msg,
                    } => {
                        // TODO: send this over the network??
                        let event = Event::handle_message(stream_id_source, msg);
                        let event_data = EventData::StreamEvent(stream_id_source, event);
                        // connection.send should receive this event
                    }
                    Message::Confirmation => continue,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let (doc_id, commit) = beelay_actor
            .create_doc(content.clone(), other_owners)
            .await
            .expect("Failed to create document");

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

        let (doc_id, _) = beelay_actor
            .create_doc(content.clone(), other_owners)
            .await
            .expect("Failed to create document");

        // Now load the document
        let loaded_doc = beelay_actor.load_doc(doc_id).await;

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

        let (doc_id, _) = beelay_actor
            .create_doc(initial_content, other_owners)
            .await
            .expect("Failed to create document");

        // Create a new commit to add
        let new_content = b"updated content".to_vec();
        let hash = CommitHash::from(blake3::hash(&new_content).as_bytes());
        let commit = Commit::new(vec![], new_content, hash);

        // Add the commit to the document
        let result = beelay_actor
            .add_commits(doc_id, vec![commit])
            .await
            .expect("Failed to add commits");

        // Verify the document now has the new commit
        let loaded_doc = beelay_actor.load_doc(doc_id).await;
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
        let contact_card = beelay_actor
            .create_contact_card()
            .await
            .expect("Failed to create contact card");

        // Verify the contact card was created successfully
        // We can't check the exact content but we can verify it exists
        assert!(contact_card.0.len() > 0, "Contact card should not be empty");
    }

    #[tokio::test]
    async fn test_beelay_actor_add_member_to_doc() {
        // Create a new BeelayActor
        let beelay_actor = spawn_beelay_actor().await;

        // First create a document
        let content = b"shared document".to_vec();
        let other_owners = vec![];

        let (doc_id, _) = beelay_actor
            .create_doc(content, other_owners)
            .await
            .expect("Failed to create document");

        // Create a contact card for a new member
        let contact_card = beelay_actor
            .create_contact_card()
            .await
            .expect("Failed to create contact card");

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
        let stream_id = actor.create_stream(target_peer_id).await;
        // let stream_id2 = actor2.accept_stream(source_peer_id).await;

    }

    #[tokio::test]
    async fn test_beelay_actor_disconnect_stream() {
        let actor = spawn_beelay_actor().await;
        let actor2 = spawn_beelay_actor().await;

        // Create a mock peer ID for testing
        let target_peer_id = actor2.peer_id();

        // First create a stream
        let stream_id = actor.create_stream(target_peer_id).await;

        // Then disconnect it
        // This should complete without error
        actor.disconnect_stream(stream_id).await;

        // Since disconnect_stream returns () (unit), we're just testing
        // that the function completes without panicking
    }


}
