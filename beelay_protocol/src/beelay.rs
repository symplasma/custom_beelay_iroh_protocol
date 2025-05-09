use beelay_core::io::{IoAction, IoResult};
use beelay_core::{conn_info, Beelay, BundleSpec, CommandId, CommandResult, CommitHash, Config, DocumentId, Event, OutboundRequestId, PeerId, StreamId, UnixTimestampMillis};
use ed25519_dalek::{SigningKey, VerifyingKey};
use signature::SignerMut;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use beelay_core::contact_card::ContactCard;
use beelay_core::keyhive::{KeyhiveCommandResult, KeyhiveEntityId, MemberAccess};
use iroh::endpoint::{RecvStream, SendStream, Source};
use iroh::NodeId;
use keyhive_core::crypto::verifiable::Verifiable;
use rand::prelude::ThreadRng;
use rand::thread_rng;

#[derive(PartialEq, Eq, Debug, Clone)]
struct IrohBeelayID(SigningKey);

impl IrohBeelayID {
    fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        Self(signing_key)
    }
    fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }

    fn key(&self) -> &SigningKey {
        &self.0
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl From<SigningKey> for IrohBeelayID {
    fn from(value: SigningKey) -> Self {
        Self(value)
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

pub struct StreamState {
    remote_peer: PeerId,
    closed: Arc<AtomicBool>,
}

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
}

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


struct BeelayBuilder {
    nickname: Option<String>,
    signing_key: Option<SigningKey>,
    storage: Option<BTreeMap<beelay_core::StorageKey, Vec<u8>>>,
    core: Option<Arc<Mutex<Beelay<ThreadRng>>>>,
}

impl BeelayBuilder {
    pub fn new() -> Self {
        Self {
            nickname: None,
            signing_key: None,
            storage: None,
            core: None,
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

    pub fn core_storage_key(mut self, 
                            core: Arc<Mutex<Beelay<ThreadRng>>>, 
                            storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
                            signing_key: SigningKey) -> Self {
        self.core = Some(core);
        self.storage = Some(storage);
        self.signing_key = Some(signing_key);
        self
    }

    fn build(self) -> BeelayContext<ThreadRng> {
        let mut signing_key = self.signing_key.unwrap_or_else(|| {
            SigningKey::generate(&mut thread_rng())
        });
        let nickname = self.nickname.unwrap_or_else(|| {
            let verifying_key = signing_key.verifying_key();
            hex::encode(verifying_key.as_bytes())
        });
        if let (Some(core), Some(storage)) =  (self.core, self.storage) {
            let peer_id = PeerId::from(signing_key.verifying_key());
            BeelayContext {
                nickname,
                signing_key,
                peer_id,
                core,
                storage,
            }
        } else {
            let config = Config::new(thread_rng(), signing_key.verifying_key());
            let mut step = beelay_core::Beelay::load(config, UnixTimestampMillis::now());
            let mut completed_tasks = Vec::new();
            let mut inbox = VecDeque::new();
            let mut storage = BTreeMap::new();
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
            let beelay_context = BeelayWrapper::generate_primed_beelay(signing_key, &*nickname, beelay, storage, inbox);
            beelay_context
        }
    }

}


pub fn build_load_beelay_core(
    nickname: &str,
    config: Config<ThreadRng>,
    mut signing_key: SigningKey,
) -> BeelayContext<ThreadRng> {
    let mut step = Beelay::load(config, UnixTimestampMillis::now());
    let mut completed_tasks = Vec::new();
    let mut inbox = VecDeque::new();
    let mut storage = BTreeMap::new();
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
    let beelay_context = BeelayWrapper::generate_primed_beelay(signing_key, nickname, beelay, storage, inbox);
    tracing::info!("loading complete");
    beelay_context
}

struct Connection {
    send: SendStream,
    recv: RecvStream
}

struct BeelayContext<R: rand::Rng + rand::CryptoRng> {
    nickname: String,
    signing_key: SigningKey,
    peer_id: PeerId,
    core: Arc<Mutex<beelay_core::Beelay<R>>>,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>
}

pub struct BeelayWrapper<R: rand::Rng + rand::CryptoRng> {
    nickname: String,
    signing_key: SigningKey,
    peer_id: PeerId,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: Arc<Mutex<beelay_core::Beelay<R>>>,

    outbox: Vec<Message>,
    inbox: VecDeque<EventData>,

    completed_commands:
        HashMap<CommandId, Result<CommandResult, beelay_core::error::Stopping>>,

    notifications: HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>>,
    peer_changes: HashMap<PeerId, Vec<conn_info::ConnectionInfo>>,

    handling_requests: HashMap<CommandId, (OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, PeerId>,

    shutdown: bool,

    streams: HashMap<StreamId, StreamState>,
    starting_streams: HashMap<CommandId, StreamState>,

    peer_connections: HashMap<PeerId, Connection>,
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> BeelayWrapper<R> {
    fn generate_primed_beelay(
        signing_key: SigningKey,
        nickname: &str,
        core: beelay_core::Beelay<R>,
        storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
        inbox: VecDeque<EventData>,
    ) -> BeelayContext<R> {
        let peer_id = PeerId::from(signing_key.verifying_key());
        let mut beelay_wrapper = Self {
            nickname: nickname.to_string(),
            signing_key,
            peer_id,
            storage,
            core: Arc::new(Mutex::new(core)),
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
            peer_connections: HashMap::new(),
        };
        
        beelay_wrapper.handle_events();

        BeelayContext {
            nickname: beelay_wrapper.nickname,
            signing_key: beelay_wrapper.signing_key,
            peer_id: beelay_wrapper.peer_id,
            core: beelay_wrapper.core,
            storage: beelay_wrapper.storage
        }
    }

    fn new(
        beelay_context: BeelayContext<R>
    ) -> Self {
        Self {
            nickname: beelay_context.nickname,
            signing_key: beelay_context.signing_key,
            peer_id: beelay_context.peer_id,
            storage: beelay_context.storage.clone(),  // TODO: fix this to be a truly shareable storage
            core: beelay_context.core,
            outbox: Vec::new(),
            inbox: VecDeque::new(),
            completed_commands: HashMap::new(),
            notifications: HashMap::new(),
            peer_changes: HashMap::new(),
            handling_requests: HashMap::new(),
            endpoints: HashMap::new(),
            shutdown: false,
            streams: HashMap::new(),
            starting_streams: HashMap::new(),
            peer_connections: HashMap::new(),
        }
    }


    pub fn handle_events(&mut self) {
        if self.shutdown {
            return;
        }
        while let Some(event) = self.inbox.pop_front() {
            let event = event.into_event();
            let now = UnixTimestampMillis::now();
            let results = {
                let mut core = self.core.lock().expect("beelay lock");
                 core.handle_event(now, event).expect("the stop should be controlled")
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
                            source: self.peer_id,
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
                        source: self.peer_id,
                        target: *peer_id,
                        senders_req_id: msg.id,
                        request: msg.request.encode(),
                    })
                }
            }
            for (id, events) in results.new_stream_events {
                for event in events {
                    tracing::trace!(?event, "stream event");
                    let StreamState {
                        remote_peer: target,
                        closed,
                    } = self.streams.get(&id).unwrap();
                    match event {
                        beelay_core::StreamEvent::Send(msg) => self.outbox.push(Message::Stream {
                            source: self.peer_id,
                            target: *target,
                            stream_id_source: id,
                            stream_id_target: None,
                            msg,
                        }),
                        beelay_core::StreamEvent::Close => {
                            closed.store(true, Ordering::SeqCst);
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
            let (command, event) =
                Event::create_doc(initial_commit.clone(), other_owners);
            self.inbox.push_back(EventData::Event(event));
            self.handle_events();
            command
        };

        // Doc is created at this point with io tasks handled.  We now have some events to deal with
        // across the network that may yield additional events to complete
        // this action in its entirety.

        self.run_until_quiescent();

        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::CreateDoc(doc_id))) => {
                let doc_id = doc_id?;
                Ok((doc_id, initial_commit))
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn contact_card(&mut self) -> Result<ContactCard, beelay_core::error::CreateContactCard> {
        let (command_id, event) = Event::create_contact_card();
        self.inbox.push_back(EventData::Event(event));
        self.run_until_quiescent();

        match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                        KeyhiveCommandResult::CreateContactCard(r),
                    ))) => r,
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
        let (command_id, event) = beelay_core::Event::add_member_to_doc(doc, member, access);
        self.inbox.push_back(EventData::Event(event));
        self.run_until_quiescent();
        match self.completed_commands.remove(&command_id) {
            Some(Ok(beelay_core::CommandResult::Keyhive(
                        beelay_core::keyhive::KeyhiveCommandResult::AddMemberToDoc,
                    ))) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn create_stream(
        &mut self,
        target: &PeerId,
        direction: beelay_core::StreamDirection,
        closed: Arc<AtomicBool>,
    ) -> beelay_core::StreamId {
        let (command, event) = Event::create_stream(direction);
        self.starting_streams.insert(
            command,
            StreamState {
                remote_peer: *target,
                closed,
            },
        );
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
        self.run_until_quiescent();
        match self.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::AddCommits(new_bundles_needed))) => {
                new_bundles_needed
            }
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
        self.run_until_quiescent();

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

        let other_peer = match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::DisconnectStream)) => self.streams.remove(&stream),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        // TODO: this is a mess, redo the tracking of streams so that we don't have to rely on reading other peer's state
        // if let Some(StreamState {
        //                 remote_peer: other_peer,
        //                 ..
        //             }) = other_peer
        // {
        //     //TODO: this needs to be passed to target over network
        //     let other_beelay = self.network.beelays.get_mut(&other_peer).unwrap();
        //     if let Some(other_stream_id) = other_beelay.streams.iter().find_map(
        //         |(
        //              other_stream_id,
        //              StreamState {
        //                  remote_peer: peer_id,
        //                  ..
        //              },
        //          )| {
        //             if peer_id == &other_peer {
        //                 Some(other_stream_id)
        //             } else {
        //                 None
        //             }
        //         },
        //     ) {
        //         let (_, evt) = Event::disconnect_stream(*other_stream_id);
        //         let event_data = EventData::Event(evt)
        //         other_beelay.inbox.push_back(evt);
        //     }
        // }

        self.run_until_quiescent();
    }

    pub fn register_endpoint(&mut self, other: &PeerId) -> beelay_core::EndpointId {
        let command = {
            let (command, event) =
                beelay_core::Event::register_endpoint(beelay_core::Audience::peer(other));
            self.inbox.push_back(EventData::Event(event));
            command
        };
        self.run_until_quiescent();
        let endpoint_id = match self.completed_commands.remove(&command) {
            Some(Ok(beelay_core::CommandResult::RegisterEndpoint(endpoint_id))) => endpoint_id,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        self.endpoints.insert(endpoint_id, *other);
        endpoint_id
    }

    pub fn run_until_quiescent(&mut self) {
        loop {
            self.handle_events();
            if self.outbox.is_empty() {
                // no actions to take on the network
                break;
            }
            let sender = self.core.peer_id();
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
                        let signed_message =
                            beelay_core::SignedMessage::decode(&request).unwrap();
                        let (command_id, event) =
                            Event::handle_request(signed_message, None);
                        // TODO: send this event over to target peer
                        let event_data = EventData::RequestEvent(command_id, event, senders_req_id, sender);
                        let connection = self.peer_connections.get_mut(&target).expect("there must be a connection in this development phase");
                        // connection.send should receive this event, command_id, sender, request_id
                    }
                    Message::Response {
                        source,
                        target,
                        id,
                        response,
                    } => {
                        let response =
                            beelay_core::EndpointResponse::decode(&response).unwrap();
                        let (_command_id, event) =
                            Event::handle_response(id, response);
                        //TODO: send this event ot target peer
                        let event_data = EventData::Event(event);
                        let connection = self.peer_connections.get_mut(&target).expect("there must be a connection in this development phase");
                        // connection.send should receive this event
                    }
                    Message::Stream {
                        source,
                        target,
                        stream_id_source,
                        stream_id_target,
                        msg } => {
                        // TODO: send this over the network??
                        let event =
                            Event::handle_message(stream_id_source, msg);
                        let event_data = EventData::StreamEvent(stream_id_source, event);
                        let connection = self.peer_connections.get_mut(&target).expect("there must be a connection in this development phase");
                        // connection.send should receive this event
                    }
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use beelay_core::Config;
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    #[tokio::test]
    async fn test_create_doc_with_contents() {
        // Setup
        let nickname = "test_user";
        let signing_key = SigningKey::generate(&mut thread_rng());
        let config = Config::new(thread_rng(), signing_key.verifying_key());
        let mut wrapper = build_load_beelay_core(nickname, config, signing_key);

        // Test data
        let content = b"test content".to_vec();
        let other_owners = vec![];

        // Act
        let (_, commit) = wrapper.create_doc_with_contents(content.clone(), other_owners).unwrap();
        println!("{:#?}", wrapper.peer_changes);

        // Assert
        assert_eq!(commit.contents(), &content);
        assert!(wrapper.outbox.is_empty(), "Outbox should be empty after initialization");
        assert!(wrapper.inbox.is_empty(), "Inbox should be empty after initialization");
        assert!(!wrapper.shutdown, "Wrapper should not be in shutdown state");
        assert!(wrapper.completed_commands.is_empty(), "No commands should be completed initially");
        assert_eq!(wrapper.notifications.len(), 1, "Notice of document discovery should be present initially");
        assert!(wrapper.peer_changes.is_empty(), "No peer changes should be present initially");
    }

    #[test]
    fn test_build_load_beelay_core() {
        // Arrange
        let nickname = "test_user";
        let signing_key = SigningKey::generate(&mut thread_rng());
        let config = Config::new(thread_rng(), signing_key.verifying_key());

        // Act
        let wrapper = build_load_beelay_core(nickname, config, signing_key);
        println!("{:?}", wrapper.storage);
        // Assert
        assert_eq!(wrapper.nickname, nickname);
        assert!(wrapper.outbox.is_empty(), "Outbox should be empty after initialization");
        assert!(wrapper.inbox.is_empty(), "Inbox should be empty after initialization");
        assert!(!wrapper.shutdown, "Wrapper should not be in shutdown state");
        assert!(wrapper.completed_commands.is_empty(), "No commands should be completed initially");
        assert!(wrapper.notifications.is_empty(), "No notifications should be present initially");
        assert!(wrapper.peer_changes.is_empty(), "No peer changes should be present initially");
    }
}