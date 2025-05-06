#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use beelay_core::{
    conn_info,
    contact_card::ContactCard,
    io::{IoAction, IoResult},
    keyhive::{KeyhiveCommandResult, KeyhiveEntityId, MemberAccess},
    BundleSpec, CommandResult, CommitHash, CommitOrBundle, DocumentId, Event, PeerId, StreamId,
    UnixTimestampMillis,
};
use ed25519_dalek::SigningKey;
use signature::SignerMut;

pub struct BeelayHandle<'a> {
    pub network: &'a mut Network,
    pub peer_id: PeerId,
}

impl BeelayHandle<'_> {
    pub fn create_doc_with_contents(
        &mut self,
        content: Vec<u8>,
        other_owners: Vec<KeyhiveEntityId>,
    ) -> Result<(DocumentId, beelay_core::Commit), beelay_core::error::Create> {
        let hash = CommitHash::from(blake3::hash(&content).as_bytes());
        let initial_commit = beelay_core::Commit::new(vec![], content, hash);
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) =
                Event::create_doc(initial_commit.clone(), other_owners);
            beelay.inbox.push_back(event);
            beelay.handle_events();
            command
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::CreateDoc(doc_id))) => {
                let doc_id = doc_id?;
                Ok((doc_id, initial_commit))
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn doc_status(&mut self, doc: &DocumentId) -> beelay_core::doc_status::DocStatus {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = Event::query_status(*doc);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();

        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::QueryStatus(status))) => status,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn add_commits(
        &mut self,
        doc_id: DocumentId,
        commits: Vec<beelay_core::Commit>,
    ) -> Result<Vec<BundleSpec>, beelay_core::error::AddCommits> {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = Event::add_commits(doc_id, commits);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::AddCommits(new_bundles_needed))) => {
                new_bundles_needed
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn load_doc(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = Event::load_doc(doc_id);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn load_doc_encrypted(&mut self, doc_id: DocumentId) -> Option<Vec<CommitOrBundle>> {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) = Event::load_doc_encrypted(doc_id);
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::LoadDoc(commits))) => commits,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn pop_notifications(
        &mut self,
    ) -> HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>> {
        std::mem::take(
            &mut self
                .network
                .beelays
                .get_mut(&self.peer_id)
                .unwrap()
                .notifications,
        )
    }

    pub fn register_endpoint(&mut self, other: &PeerId) -> beelay_core::EndpointId {
        let command = {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let (command, event) =
                Event::register_endpoint(beelay_core::Audience::peer(other));
            beelay.inbox.push_back(event);
            command
        };
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let endpoint_id = match beelay.completed_commands.remove(&command) {
            Some(Ok(CommandResult::RegisterEndpoint(endpoint_id))) => endpoint_id,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        beelay.endpoints.insert(endpoint_id, *other);
        endpoint_id
    }

    pub fn dirty_shutdown(&mut self) {
        self.network
            .beelays
            .get_mut(&self.peer_id)
            .unwrap()
            .shutdown = true;
    }

    pub fn shutdown(&mut self) {
        {
            let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
            let event = Event::stop();
            beelay.inbox.push_back(event);
        }
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let mut iterations = 0;
        loop {
            if beelay.shutdown {
                break;
            }
            iterations += 1;
            if iterations > 100 {
                panic!("shutdown didn't complete after 100 iterations");
            }
            beelay.handle_events();
        }
    }

    pub fn add_member_to_doc(
        &mut self,
        doc: DocumentId,
        member: KeyhiveEntityId,
        access: MemberAccess,
    ) {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::add_member_to_doc(doc, member, access);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::AddMemberToDoc,
            ))) => (),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn remove_member_from_doc(
        &mut self,
        doc: DocumentId,
        member: KeyhiveEntityId,
    ) -> Result<(), beelay_core::error::RemoveMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::remove_member_from_doc(doc, member);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::RemoveMemberFromDoc(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn create_group(
        &mut self,
        other_parents: Vec<KeyhiveEntityId>,
    ) -> Result<PeerId, beelay_core::error::CreateGroup> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::create_group(other_parents);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(KeyhiveCommandResult::CreateGroup(r)))) => {
                r
            }
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn add_member_to_group(
        &mut self,
        add: beelay_core::keyhive::AddMemberToGroup,
    ) -> Result<(), beelay_core::error::AddMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::add_member_to_group(add);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::AddMemberToGroup(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn remove_member_from_group(
        &mut self,
        remove: beelay_core::keyhive::RemoveMemberFromGroup,
    ) -> Result<(), beelay_core::error::RemoveMember> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::remove_member_from_group(remove);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::RemoveMemberFromGroup(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn query_access(
        &mut self,
        doc: DocumentId,
    ) -> Result<
        HashMap<PeerId, MemberAccess>,
        beelay_core::error::QueryAccess,
    > {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::query_access(doc);
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::QueryAccess(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn storage(&self) -> &BTreeMap<beelay_core::StorageKey, Vec<u8>> {
        &self.network.beelays.get(&self.peer_id).unwrap().storage
    }

    // #[cfg(feature = "debug_events")]
    // pub fn log_keyhive_events(
    //     &mut self,
    //     nicknames: keyhive_core::debug_events::Nicknames,
    // ) -> keyhive_core::debug_events::DebugEventTable {
    //     let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
    //     let (command_id, event) = beelay_core::Event::log_keyhive_events(nicknames);
    //     beelay.inbox.push_back(event);
    //     self.network.run_until_quiescent();
    //     let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
    // 
    //     match beelay.completed_commands.remove(&command_id) {
    //         Some(Ok(beelay_core::CommandResult::Keyhive(
    //             beelay_core::keyhive::KeyhiveCommandResult::DebugEvents(events),
    //         ))) => events,
    //         Some(other) => panic!("unexpected command result: {:?}", other),
    //         None => panic!("no command result"),
    //     }
    // }

    pub fn contact_card(&mut self) -> Result<ContactCard, beelay_core::error::CreateContactCard> {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::create_contact_card();
        beelay.inbox.push_back(event);
        self.network.run_until_quiescent();
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();

        match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::Keyhive(
                KeyhiveCommandResult::CreateContactCard(r),
            ))) => r,
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        }
    }

    pub fn num_sessions(&self) -> usize {
        let beelay = self.network.beelays.get(&self.peer_id).unwrap();
        beelay.core.num_sessions()
    }

    pub fn advance_time(&mut self, duration: Duration) {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        beelay.now += duration;
        beelay.inbox.push_back(Event::tick());
        self.network.run_until_quiescent();
    }

    pub fn conn_info(&mut self) -> HashMap<StreamId, conn_info::ConnectionInfo> {
        let beelay = self.network.beelays.get(&self.peer_id).unwrap();
        beelay.core.connection_info()
    }

    pub fn disconnect(&mut self, stream: StreamId) {
        let beelay = self.network.beelays.get_mut(&self.peer_id).unwrap();
        let (command_id, event) = Event::disconnect_stream(stream);
        beelay.inbox.push_back(event);

        beelay.handle_events();

        let other_peer = match beelay.completed_commands.remove(&command_id) {
            Some(Ok(CommandResult::DisconnectStream)) => beelay.streams.remove(&stream),
            Some(other) => panic!("unexpected command result: {:?}", other),
            None => panic!("no command result"),
        };
        if let Some(StreamState {
            remote_peer: other_peer,
            ..
        }) = other_peer
        {
            let other_beelay = self.network.beelays.get_mut(&other_peer).unwrap();
            if let Some(other_stream_id) = other_beelay.streams.iter().find_map(
                |(
                    other_stream_id,
                    StreamState {
                        remote_peer: peer_id,
                        ..
                    },
                )| {
                    if peer_id == &other_peer {
                        Some(other_stream_id)
                    } else {
                        None
                    }
                },
            ) {
                let (_, evt) = Event::disconnect_stream(*other_stream_id);
                other_beelay.inbox.push_back(evt);
            }
        }

        self.network.run_until_quiescent();
    }

    pub fn peer_changes(&self) -> &HashMap<PeerId, Vec<conn_info::ConnectionInfo>> {
        &self
            .network
            .beelays
            .get(&self.peer_id)
            .unwrap()
            .peer_changes
    }
}

pub struct Network {
    beelays: HashMap<PeerId, BeelayWrapper<rand::rngs::ThreadRng>>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            beelays: HashMap::new(),
        }
    }

    pub fn beelay(&mut self, peer: &PeerId) -> BeelayHandle {
        assert!(self.beelays.contains_key(peer));
        BeelayHandle {
            network: self,
            peer_id: *peer,
        }
    }
    // 
    // pub fn create_peer(&mut self, nickname: &'static str) -> PeerBuilder {
    //     PeerBuilder {
    //         network: self,
    //         storage: BTreeMap::new(),
    //         nickname,
    //         session_duration: Duration::from_secs(3600),
    //         signing_key: SigningKey::generate(&mut rand::thread_rng()),
    //     }
    // }

    pub(crate) fn load_peer(
        &mut self,
        nickname: &str,
        config: beelay_core::Config<rand::rngs::ThreadRng>,
        mut storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
        mut signing_key: SigningKey,
    ) -> PeerId {
        let mut step = beelay_core::Beelay::load(config, UnixTimestampMillis::now());
        let mut completed_tasks = Vec::new();
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

        let peer_id = beelay.peer_id();
        let mut beelay = BeelayWrapper::new(signing_key, nickname, beelay);
        beelay.storage = storage;
        for result in completed_tasks {
            beelay.inbox.push_back(Event::io_complete(result));
        }
        // beelay.handle_events();
        self.beelays.insert(peer_id, beelay);
        self.run_until_quiescent();
        tracing::info!("loading complete");
        peer_id
    }

    // pub fn reload_peer(&mut self, peer: &PeerId) {
    //     {
    //         let mut beelay = self.beelay(peer);
    //         beelay.shutdown();
    //     }
    //     let beelay = self.beelays.remove(peer).unwrap();
    //     let config =
    //         beelay_core::Config::new(rand::thread_rng(), beelay.signing_key.verifying_key());
    //     self.load_peer(&beelay.nickname, config, beelay.storage, beelay.signing_key);
    // }

    // Create a stream from left to right (i.e., the left peer will send the hello message)
    // pub fn connect_stream(&mut self, left: &PeerId, right: &PeerId) -> ConnectedPair {
    //     let left_closed = Arc::new(AtomicBool::new(false));
    //     let right_closed = Arc::new(AtomicBool::new(false));
    // 
    //     let left_stream_id = {
    //         let beelay = self.beelays.get_mut(left).unwrap();
    //         beelay.create_stream(
    //             right,
    //             beelay_core::StreamDirection::Connecting {
    //                 remote_audience: beelay_core::Audience::peer(right),
    //             },
    //             left_closed.clone(),
    //         )
    //     };
    //     let right_stream_id = {
    //         let beelay = self.beelays.get_mut(right).unwrap();
    //         beelay.create_stream(
    //             left,
    //             beelay_core::StreamDirection::Accepting {
    //                 receive_audience: None,
    //             },
    //             right_closed.clone(),
    //         )
    //     };
    //     self.run_until_quiescent();
    //     ConnectedPair {
    //         left_closed,
    //         left_to_right: left_stream_id,
    //         right_closed,
    //         right_to_left: right_stream_id,
    //     }
    // }

    pub fn run_until_quiescent(&mut self) {
        loop {
            let mut messages_this_round = HashMap::new();

            for (source_id, beelay) in self.beelays.iter_mut() {
                beelay.handle_events();
                if !beelay.outbox.is_empty() {
                    messages_this_round.insert(*source_id, std::mem::take(&mut beelay.outbox));
                }
            }
            if messages_this_round.is_empty() {
                break;
            }
            for (sender, outbound) in messages_this_round {
                for msg in outbound {
                    match msg {
                        Message::Request {
                            target,
                            senders_req_id,
                            request,
                        } => {
                            let target_beelay = self.beelays.get_mut(&target).unwrap();
                            let signed_message =
                                beelay_core::SignedMessage::decode(&request).unwrap();
                            let (command_id, event) =
                                Event::handle_request(signed_message, None);
                            target_beelay.inbox.push_back(event);
                            target_beelay
                                .handling_requests
                                .insert(command_id, (senders_req_id, sender));
                        }
                        Message::Response {
                            target,
                            id,
                            response,
                        } => {
                            let target = self.beelays.get_mut(&target).unwrap();
                            let response =
                                beelay_core::EndpointResponse::decode(&response).unwrap();
                            let (_command_id, event) =
                                Event::handle_response(id, response);
                            target.inbox.push_back(event);
                        }
                        Message::Stream { target, msg } => {
                            let target_beelay = self.beelays.get_mut(&target).unwrap();
                            let incoming_stream_id = target_beelay
                                .streams
                                .iter()
                                .find_map(
                                    |(
                                        stream,
                                        StreamState {
                                            remote_peer: peer, ..
                                        },
                                    )| {
                                        if *peer == sender {
                                            Some(stream)
                                        } else {
                                            None
                                        }
                                    },
                                )
                                .unwrap();
                            let event =
                                Event::handle_message(*incoming_stream_id, msg);
                            target_beelay.inbox.push_back(event);
                        }
                    }
                }
            }
        }
    }

    pub fn advance_time(&mut self, duration: Duration) {
        for (_, beelay) in self.beelays.iter_mut() {
            beelay.now += duration;
            beelay.inbox.push_back(Event::tick());
        }
        self.run_until_quiescent();
    }
}

enum Message {
    Request {
        target: PeerId,
        senders_req_id: beelay_core::OutboundRequestId,
        request: Vec<u8>,
    },
    Response {
        target: PeerId,
        id: beelay_core::OutboundRequestId,
        response: Vec<u8>,
    },
    Stream {
        target: PeerId,
        msg: Vec<u8>,
    },
}

pub struct BeelayWrapper<R: rand::Rng + rand::CryptoRng> {
    nickname: String,
    signing_key: SigningKey,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
    core: beelay_core::Beelay<R>,
    outbox: Vec<Message>,
    inbox: VecDeque<Event>,
    completed_commands: HashMap<
        beelay_core::CommandId,
        Result<CommandResult, beelay_core::error::Stopping>,
    >,
    notifications: HashMap<DocumentId, Vec<beelay_core::doc_status::DocEvent>>,
    peer_changes: HashMap<PeerId, Vec<conn_info::ConnectionInfo>>,
    handling_requests: HashMap<beelay_core::CommandId, (beelay_core::OutboundRequestId, PeerId)>,
    endpoints: HashMap<beelay_core::EndpointId, PeerId>,
    streams: HashMap<StreamId, StreamState>,
    starting_streams: HashMap<beelay_core::CommandId, StreamState>,
    shutdown: bool,
    now: UnixTimestampMillis,
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> BeelayWrapper<R> {
    fn new(signing_key: SigningKey, nickname: &str, core: beelay_core::Beelay<R>) -> Self {
        Self {
            nickname: nickname.to_string(),
            signing_key,
            storage: BTreeMap::new(),
            core,
            outbox: Vec::new(),
            inbox: VecDeque::new(),
            completed_commands: HashMap::new(),
            notifications: HashMap::new(),
            peer_changes: HashMap::new(),
            handling_requests: HashMap::new(),
            endpoints: HashMap::new(),
            streams: HashMap::new(),
            starting_streams: HashMap::new(),
            shutdown: false,
            now: UnixTimestampMillis::now(),
        }
    }

    pub fn create_stream(
        &mut self,
        target: &PeerId,
        direction: beelay_core::StreamDirection,
        closed: Arc<AtomicBool>,
    ) -> StreamId {
        let (command, event) = Event::create_stream(direction);
        self.starting_streams.insert(
            command,
            StreamState {
                remote_peer: *target,
                closed,
            },
        );
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

    pub fn handle_events(&mut self) {
        if self.shutdown {
            return;
        }
        while let Some(event) = self.inbox.pop_front() {
            self.now += Duration::from_millis(10);
            let results = self.core.handle_event(self.now, event).unwrap();
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
                    self.streams.insert(stream_id, target);
                }
                if let Ok(CommandResult::HandleRequest(response)) = &result {
                    let Ok(response) = response else {
                        continue;
                    };
                    if let Some((sender_req_id, sender)) = self.handling_requests.remove(&command) {
                        self.outbox.push(Message::Response {
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
                            target: *target,
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

pub struct ConnectedPair {
    pub left_closed: Arc<AtomicBool>,
    pub left_to_right: StreamId,
    pub right_closed: Arc<AtomicBool>,
    pub right_to_left: StreamId,
}

pub struct StreamState {
    remote_peer: PeerId,
    closed: Arc<AtomicBool>,
}

pub struct PeerBuilder<'a> {
    network: &'a mut Network,
    nickname: &'static str,
    session_duration: Duration,
    signing_key: SigningKey,
    storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>,
}

impl PeerBuilder<'_> {
    pub fn session_duration(mut self, duration: Duration) -> Self {
        self.session_duration = duration;
        self
    }

    pub fn signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = key;
        self
    }

    pub fn storage(mut self, storage: BTreeMap<beelay_core::StorageKey, Vec<u8>>) -> Self {
        self.storage = storage;
        self
    }

    pub fn build(self) -> PeerId {
        let config = beelay_core::Config::new(rand::thread_rng(), self.signing_key.verifying_key())
            .session_duration(self.session_duration);
        self.network
            .load_peer(self.nickname, config, self.storage, self.signing_key)
    }
}
