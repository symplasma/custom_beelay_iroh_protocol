use crate::actor::{ActionResult, BeelayAction};
use crate::messages::Message;
use crate::primitives::StreamState;
use crate::storage_handling;
use crate::storage_handling::BeelayStorage;
use beelay_core::contact_card::ContactCard;
use beelay_core::error::{AddCommits, CreateContactCard};
use beelay_core::keyhive::{KeyhiveCommandResult, KeyhiveEntityId, MemberAccess};
use beelay_core::{
    Beelay, BundleSpec, CommandId, CommandResult, Commit, CommitHash, CommitOrBundle, Config,
    DocumentId, Event, OutboundRequestId, PeerId, StreamDirection, StreamId, UnixTimestampMillis,
    conn_info,
};
use ed25519_dalek::SigningKey;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Debug;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

/// This is the main entry point for building a Beelay state machine and ensuring it is either properly loaded from storage or built from scratch.
pub struct BeelayBuilder {
    signing_key: Option<SigningKey>,
    storage: Option<BeelayStorage>,
    recv_channel: Option<Receiver<BeelayAction>>,
    send_channel: Option<Sender<BeelayAction>>,
}

impl BeelayBuilder {
    pub fn new() -> Self {
        Self {
            signing_key: None,
            storage: None,
            recv_channel: None,
            send_channel: None,
        }
    }

    pub fn signing_key(mut self, signing_key: SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    pub fn storage(mut self, storage: BeelayStorage) -> Self {
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

    pub(crate) fn build(self) -> BeelayWrapper<ThreadRng> {
        let mut storage = match self.storage {
            Some(storage) => {
                if self.signing_key.is_none() {
                    panic!("signing key must be provided when loading from storage");
                }
                storage
            }
            None => BTreeMap::new(),
        };
        let mut signing_key = self
            .signing_key
            .unwrap_or_else(|| SigningKey::generate(&mut thread_rng()));

        let (recv_channel, send_channel) = if let (Some(recv_channel), Some(send_channel)) =
            (self.recv_channel, self.send_channel)
        {
            (recv_channel, send_channel)
        } else {
            let (sender, receiver) = mpsc::channel(100);
            (receiver, sender)
        };

        let config = Config::new(thread_rng(), signing_key.verifying_key());
        let mut step = Beelay::load(config, UnixTimestampMillis::now());
        let mut completed_tasks = Vec::new();
        let mut inbox = VecDeque::new();
        let beelay = loop {
            match step {
                beelay_core::loading::Step::Loading(loading, io_tasks) => {
                    for task in io_tasks {
                        let result =
                            storage_handling::handle_task(&mut storage, &mut signing_key, task);
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
                        let result =
                            storage_handling::handle_task(&mut storage, &mut signing_key, task);
                        completed_tasks.push(result);
                    }
                    break beelay;
                }
            }
        };
        for result in completed_tasks {
            inbox.push_back(Event::io_complete(result));
        }
        BeelayWrapper::generate_primed_beelay(
            signing_key,
            beelay,
            storage,
            inbox,
            recv_channel,
            send_channel,
        )
    }
}

pub struct BeelayWrapper<R: rand::Rng + rand::CryptoRng> {
    signing_key: SigningKey,
    storage: BeelayStorage,
    core: Beelay<R>,

    outbox: VecDeque<Message>,
    inbox: VecDeque<Event>,

    completed_commands: HashMap<CommandId, Result<CommandResult, beelay_core::error::Stopping>>,

    notifications: HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>>,
    peer_changes: HashMap<PeerId, Vec<conn_info::ConnectionInfo>>,

    handling_requests: HashMap<CommandId, (OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, PeerId>,

    shutdown: bool,

    streams: HashMap<StreamId, StreamState>,
    starting_streams: HashMap<CommandId, PeerId>,

    recv_channel: Receiver<BeelayAction>,
    send_channel: Sender<BeelayAction>, // linked here in case we need a feedback mechanism
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> BeelayWrapper<R> {
    fn generate_primed_beelay(
        signing_key: SigningKey,
        core: Beelay<R>,
        storage: BeelayStorage,
        inbox: VecDeque<Event>,
        recv_channel: Receiver<BeelayAction>,
        send_channel: Sender<BeelayAction>,
    ) -> BeelayWrapper<R> {
        let mut beelay_wrapper = Self {
            signing_key,
            storage,
            core,
            outbox: VecDeque::new(),
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
            let now = UnixTimestampMillis::now();
            let results = {
                self.core
                    .handle_event(now, event)
                    .expect("the stop should be controlled")
            };
            for task in results.new_tasks.into_iter() {
                let event = self.handle_task(task);
                self.inbox.push_back(event);
            }

            for (command, result) in results.completed_commands.into_iter() {
                if let Ok(CommandResult::CreateStream(stream_id)) = result {
                    let target = self
                        .starting_streams
                        .remove(&command)
                        .expect("should be a starting stream registered");
                    let stream_state = StreamState::connect(target, stream_id);
                    self.streams.insert(stream_id, stream_state);
                }
                if let Ok(CommandResult::HandleRequest(response)) = &result {
                    let Ok(response) = response else {
                        continue;
                    };
                    if let Some((sender_req_id, sender)) = self.handling_requests.remove(&command) {
                        self.outbox.push_back(Message::Response {
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
                    self.outbox.push_back(Message::Request {
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
                    let stream_state = self.streams.get(&id).unwrap();
                    match event {
                        beelay_core::StreamEvent::Send(msg) => {
                            let outgoing_message =
                                if let Some(target_stream_id) = stream_state.target_stream_id() {
                                    Message::Stream {
                                        source: self.peer_id(),
                                        target: stream_state.target_peer_id(),
                                        stream_id_source: id,
                                        stream_id_target: target_stream_id,
                                        msg,
                                    }
                                } else {
                                    Message::StreamConnect {
                                        source: self.peer_id(),
                                        target: stream_state.target_peer_id(),
                                        stream_id_source: id,
                                        msg,
                                    }
                                };
                            self.outbox.push_back(outgoing_message);
                        }
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
    }

    pub fn handle_task(&mut self, task: beelay_core::io::IoTask) -> Event {
        let result = storage_handling::handle_task(&mut self.storage, &mut self.signing_key, task);
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
    ) -> Result<(DocumentId, Commit), beelay_core::error::Create> {
        let hash = CommitHash::from(blake3::hash(&content).as_bytes());
        let initial_commit = Commit::new(vec![], content, hash);
        let command = {
            let (command, event) = Event::create_doc(initial_commit.clone(), other_owners);
            self.inbox.push_back(event);
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
            self.inbox.push_back(event);
            command
        };
        self.handle_events();
        match self.completed_commands.remove(&command) {
            Some(Ok(CommandResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn contact_card(&mut self) -> Result<ContactCard, CreateContactCard> {
        let (command_id, event) = Event::create_contact_card();
        self.inbox.push_back(event);
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
        self.inbox.push_back(event);
        self.handle_events();
        match self.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(KeyhiveCommandResult::AddMemberToDoc))) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn create_stream(&mut self, target: &PeerId, direction: StreamDirection) -> StreamId {
        let (command, event) = Event::create_stream(direction);
        self.starting_streams.insert(command, *target);
        self.inbox.push_back(event);
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
        commits: Vec<Commit>,
    ) -> Result<Vec<BundleSpec>, AddCommits> {
        let command = {
            let (command, event) = Event::add_commits(doc_id, commits);
            self.inbox.push_back(event);
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
            self.inbox.push_back(event);
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
        self.inbox.push_back(event);

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
            self.inbox.push_back(event);
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

    pub fn output_storage(&self) {
        println!("storage size: {:?}", self.storage.len());
        for entry in self.storage.iter() {
            println!("{:?}", entry);
        }
    }

    pub async fn process_actions(&mut self) {
        while let Some(action) = self.recv_channel.recv().await {
            match action {
                BeelayAction::CreateDoc(reply, content, other_owners) => {
                    let other_owners = other_owners.into_iter().map(|x| x.into()).collect();
                    let result = self.create_doc_with_contents(content, other_owners);
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::LoadDoc(reply, doc_id) => {
                    let result = self.load_doc(doc_id);
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::DocStatus(reply, doc_id) => {
                    let result = self.doc_status(&doc_id);
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::AddCommits(reply, doc_id, commits) => {
                    let result = self.add_commits(doc_id, commits);
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::CreateContactCard(reply) => {
                    let result = match self.contact_card() {
                        Ok(contact_card) => Ok(contact_card.into()),
                        Err(e) => Err(e),
                    };
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::AddMemberToDoc(reply, doc_id, member, access) => {
                    self.add_member_to_doc(doc_id, member.into(), access);
                    let action_result = self.process_result(());
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::CreateStream(reply, target) => {
                    let result = self.create_stream(
                        &target,
                        StreamDirection::Connecting {
                            remote_audience: beelay_core::Audience::peer(&target),
                        },
                    );
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::AcceptStream(reply, target) => {
                    let result = self.create_stream(
                        &target,
                        StreamDirection::Accepting {
                            receive_audience: None,
                        },
                    );
                    let action_result = self.process_result(result);
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::DisconnectStream(reply, stream_id) => {
                    self.disconnect(stream_id);
                    let action_result = self.process_result(());
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::SendMessage(reply, message) => {
                    self.process_message(message);
                    self.handle_events();
                    let action_result = self.process_result(());
                    reply.send(action_result).expect("send failed for action");
                }
                BeelayAction::DisplayStorage(reply) => {
                    self.output_storage();
                    let action_result = self.process_result(());
                    reply.send(action_result).unwrap()
                }
            }
        }
    }

    fn process_result<T: Debug>(&mut self, result: T) -> ActionResult<T> {
        let outbox = std::mem::take(&mut self.outbox);
        ActionResult::new(result, outbox)
    }

    pub fn process_message(&mut self, message: Message) {
        match message {
            Message::Request {
                source,
                target,
                senders_req_id,
                request,
            } => {
                let signed_message = beelay_core::SignedMessage::decode(&request).unwrap();
                let (_command_id, event) = Event::handle_request(signed_message, None);
                self.inbox.push_back(event);
            }
            Message::Response {
                source,
                target,
                id,
                response,
            } => {
                let response = beelay_core::EndpointResponse::decode(&response).unwrap();
                let (_command_id, event) = Event::handle_response(id, response);
                self.inbox.push_back(event);
            }
            Message::StreamConnect {
                source,
                target,
                stream_id_source,
                msg,
            } => {
                let accepting_stream_id = self.create_stream(
                    &source,
                    StreamDirection::Accepting {
                        receive_audience: None,
                    },
                );
                let stream_state = self
                    .streams
                    .get_mut(&accepting_stream_id)
                    .expect("stream state should exist");
                stream_state.set_target_stream_id(stream_id_source);

                // need to send a stream Accepted message to give the other end this side's stream id
                let accepted = Message::StreamAccept {
                    source: target,
                    target: source,
                    stream_id_source: accepting_stream_id,
                    stream_id_target: stream_id_source,
                };
                self.outbox.push_front(accepted);

                let event = Event::handle_message(accepting_stream_id, msg);
                self.inbox.push_back(event)
            }
            Message::StreamAccept {
                source,
                target,
                stream_id_source,
                stream_id_target,
            } => {
                let stream_state = self
                    .streams
                    .get_mut(&stream_id_target)
                    .expect("stream state should exist");
                stream_state.set_target_stream_id(stream_id_source);
            }
            Message::Stream {
                source,
                target,
                stream_id_source,
                stream_id_target,
                msg,
            } => {
                let event = Event::handle_message(stream_id_target, msg);
                self.inbox.push_back(event);
            }
            Message::Confirmation { .. } => {} // for potential later usage for negotiating external events
            _ => unimplemented!(),
        }
    }
}
