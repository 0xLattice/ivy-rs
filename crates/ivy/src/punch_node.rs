//! Native node wrapper that consumes punch control messages and upgrades relayed
//! sessions over simultaneous-open TCP. Application events retain their IDs.
use crate::{
    node::{SuppliedDirection, SuppliedStream},
    punch_transport::{PreparedPunch, PunchTransport, PunchedStream, TcpPunchTransport},
};
use ivy_core::{
    core::{AuthenticatedPeer, CoreSettings, Effect, Event, Request, RequestResult},
    punch::{Signal, TOPIC},
    punch_connector::{Action, Connector, Options},
    Config, Message, PeerEndpoint,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::Arc,
};
const MAX_QUEUED_NODE_EVENTS: usize = 8192;
fn queue_node(queue: &mut VecDeque<Event>, event: Event) -> io::Result<()> {
    if queue.len() >= MAX_QUEUED_NODE_EVENTS {
        return Err(io::Error::other("node command backpressure limit exceeded"));
    }
    queue.push_back(event);
    Ok(())
}

use tokio::{
    net::TcpListener,
    sync::mpsc,
    task::{AbortHandle, JoinSet},
    time::Instant,
};
pub struct Settings {
    pub config: Config,
    pub core: CoreSettings,
    pub punch: Options,
    pub hosts: Option<Vec<String>>,
}
pub enum Command {
    Node(Event),
    Upgrade(AuthenticatedPeer),
}
#[derive(Debug)]
pub enum Notification {
    Node(Effect),
    UpgradeFinished {
        peer: AuthenticatedPeer,
        direct: bool,
    },
}
enum Pending {
    User(u64),
    Internal,
    Signal {
        ticket: u64,
        peer: AuthenticatedPeer,
        signal: Signal,
        waiting: bool,
    },
    Connect {
        ticket: u64,
        peer: AuthenticatedPeer,
    },
}
struct DialResult {
    ticket: u64,
    peer: AuthenticatedPeer,
    initiator: bool,
    stream: io::Result<PunchedStream>,
}
enum WorkResult {
    Prepared {
        ticket: u64,
        peer: AuthenticatedPeer,
        attempt: io::Result<Box<dyn PreparedPunch>>,
    },
    Dial(DialResult),
}
/// Owns all background work. Stop, command-channel closure and cancellation drop
/// every prepared/dialling socket; streams already handed to Core belong to it.
pub async fn run(
    listener: TcpListener,
    settings: Settings,
    commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<Notification>,
    ledger: impl ivy_core::PeerLedger + 'static,
) -> io::Result<()> {
    run_with_transport(
        listener,
        settings,
        commands,
        notifications,
        ledger,
        TcpPunchTransport,
    )
    .await
}
/// Runs the same coordinator using an application-provided punch transport.
/// Preparation and connection futures are cancelled on timeout/session loss.
pub async fn run_with_transport(
    listener: TcpListener,
    settings: Settings,
    commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<Notification>,
    ledger: impl ivy_core::PeerLedger + 'static,
    transport: impl PunchTransport + 'static,
) -> io::Result<()> {
    run_with_supplied_shutdown(
        listener,
        settings,
        commands,
        notifications,
        ledger,
        transport,
        None,
        std::future::pending(),
    )
    .await
}

/// Punch coordination and external streams share the same authenticated Core.
/// Out-of-band shutdown interrupts backpressured delivery and awaits every
/// transport task. Outbound supplied streams retain the caller's request IDs.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_supplied_shutdown(
    listener: TcpListener,
    settings: Settings,
    commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<Notification>,
    ledger: impl ivy_core::PeerLedger + 'static,
    transport: impl PunchTransport + 'static,
    supplied: Option<mpsc::Receiver<SuppliedStream>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    run_coordinator(
        listener,
        settings,
        commands,
        notifications,
        ledger,
        transport,
        supplied,
        shutdown,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_coordinator(
    listener: TcpListener,
    settings: Settings,
    mut commands: mpsc::Receiver<Command>,
    notifications: mpsc::Sender<Notification>,
    ledger: impl ivy_core::PeerLedger + 'static,
    transport: impl PunchTransport + 'static,
    mut supplied: Option<mpsc::Receiver<SuppliedStream>>,
    shutdown: impl std::future::Future<Output = ()>,
    disconnect_failed: bool,
) -> io::Result<()> {
    let transport = Arc::new(transport);
    let origin = Instant::now();
    let mut coordinator = Connector::new(settings.config.peer_key(), settings.punch.clone());
    let mut public_host = settings
        .core
        .external_address
        .as_ref()
        .map(|a| a.host.clone());
    let (node_commands, node_rx) = mpsc::channel(256);
    let (node_notifications, mut effects) = mpsc::channel(256);
    let (streams, node_streams) = mpsc::channel(16);
    let mut node = JoinSet::new();
    let (stop_node, stopped) = tokio::sync::oneshot::channel();
    node.spawn(crate::node::run_with_shutdown(
        listener,
        settings.config,
        settings.core,
        node_rx,
        node_notifications,
        Some(node_streams),
        ledger,
        async move {
            let _ = stopped.await;
        },
    ));
    let mut sockets: BTreeMap<u64, Box<dyn PreparedPunch>> = BTreeMap::new();
    let mut tasks = JoinSet::new();
    let mut handles: BTreeMap<u64, AbortHandle> = BTreeMap::new();
    let mut next = 0u64;
    let mut pending: BTreeMap<u64, Pending> = BTreeMap::new();
    let mut external: BTreeMap<u64, u64> = BTreeMap::new();
    let mut actions = VecDeque::new();
    let mut node_outbox = VecDeque::new();
    let mut supplied_outbox = VecDeque::new();
    let mut deferred_dials = BTreeMap::new();
    macro_rules! request {
        ($kind:expr,$request:expr) => {{
            next = next
                .checked_add(1)
                .ok_or_else(|| io::Error::other("request IDs exhausted"))?;
            pending.insert(next, $kind);
            queue_node(&mut node_outbox, Event::Request(next, $request))?;
            next
        }};
    }
    let coordinate = async {
        loop {
            while let Some(action) = actions.pop_front() {
                match action {
                    Action::Prepare { ticket, peer } => {
                        let hosts = settings
                            .hosts
                            .clone()
                            .unwrap_or_else(|| public_host.clone().into_iter().collect());
                        let transport = transport.clone();
                        let handle = tasks.spawn(async move {
                            WorkResult::Prepared {
                                ticket,
                                peer,
                                attempt: transport.prepare(hosts).await,
                            }
                        });
                        handles.insert(ticket, handle);
                    }
                    Action::Send {
                        ticket,
                        peer,
                        signal,
                    } => {
                        if let Some(payload) = signal.encode() {
                            request!(
                                Pending::Signal {
                                    ticket,
                                    peer: peer.clone(),
                                    signal,
                                    waiting: false
                                },
                                Request::Send {
                                    peer: peer.key,
                                    session_id: Some(peer.session_id),
                                    message: Message::PeerMessage {
                                        topic: TOPIC.into(),
                                        payload
                                    }
                                }
                            );
                        }
                    }
                    Action::Dial {
                        ticket,
                        peer,
                        candidates,
                        initiator,
                        at,
                        deadline,
                    } => {
                        if pending.values().any(
                        |p| matches!(p, Pending::Signal{ticket: active, ..} if *active == ticket),
                    ) {
                        deferred_dials.insert(
                            ticket,
                            Action::Dial {
                                ticket,
                                peer,
                                candidates,
                                initiator,
                                at,
                                deadline,
                            },
                        );
                        continue;
                    }
                        let Some(socket) = sockets.remove(&ticket) else {
                            actions.extend(coordinator.failed(ticket, &peer));
                            continue;
                        };
                        let private = settings.punch.allow_private_candidates;
                        let handle = tasks.spawn(async move {
                            tokio::time::sleep_until(origin + at).await;
                            let stream = tokio::time::timeout_at(
                                origin + deadline,
                                socket.connect(candidates, private, origin + deadline),
                            )
                            .await
                            .unwrap_or_else(|_| {
                                Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "punch transport deadline expired",
                                ))
                            });
                            WorkResult::Dial(DialResult {
                                ticket,
                                peer,
                                initiator,
                                stream,
                            })
                        });
                        handles.insert(ticket, handle);
                    }
                    Action::Release { ticket, .. } => {
                        sockets.remove(&ticket);
                        deferred_dials.remove(&ticket);
                        let obsolete: Vec<_> = pending
                            .iter()
                            .filter_map(|(id, p)| match p {
                                Pending::Signal {
                                    ticket: pending_ticket,
                                    ..
                                } if *pending_ticket == ticket => Some(*id),
                                _ => None,
                            })
                            .collect();
                        for id in obsolete {
                            pending.remove(&id);
                            queue_node(&mut node_outbox, Event::Cancel(id))?;
                        }
                        if let Some(handle) = handles.remove(&ticket) {
                            handle.abort();
                        }
                    }
                    Action::Finished { peer, direct } => {
                        if disconnect_failed && !direct {
                            request!(Pending::Internal, Request::Disconnect(peer.clone()));
                        }
                        if notifications
                            .send(Notification::UpgradeFinished { peer, direct })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            tokio::select! {
                command=commands.recv(), if node_outbox.len() < MAX_QUEUED_NODE_EVENTS =>match command {
                    Some(Command::Upgrade(peer))=>actions.extend(coordinator.upgrade(&peer,origin.elapsed())),
                        Some(Command::Node(Event::Request(id,request)))=>{if let std::collections::btree_map::Entry::Vacant(entry) = external.entry(id) { let internal=request!(Pending::User(id),request);entry.insert(internal); }}
                    Some(Command::Node(Event::Cancel(id)))=>{if let Some(internal)=external.get(&id){queue_node(&mut node_outbox,Event::Cancel(*internal))?;}}
                    Some(Command::Node(Event::Stop))|None=>break,
                    Some(Command::Node(event))=>queue_node(&mut node_outbox,event)?,
                },
                incoming=async { match &mut supplied {
                    Some(channel)=>channel.recv().await,
                    None=>std::future::pending().await,
                }}, if supplied_outbox.len() < 16 && node_outbox.len() < MAX_QUEUED_NODE_EVENTS=>{
                    let Some(mut incoming)=incoming else { supplied=None; continue; };
                    let caller=match &mut incoming.direction {
                        SuppliedDirection::Connect{request,..}|SuppliedDirection::ConnectWithLocal{request,..}=>Some(request),
                        _=>None,
                    };
                    if let Some(caller)=caller {
                        if external.contains_key(caller) { continue; }
                        next=next.checked_add(1).ok_or_else(||io::Error::other("request IDs exhausted"))?;
                        pending.insert(next,Pending::User(*caller));external.insert(*caller,next);*caller=next;
                    }
                    supplied_outbox.push_back(incoming);
                },
                permit=node_commands.reserve(), if !node_outbox.is_empty()=>{
                    match permit { Ok(permit)=>{permit.send(node_outbox.pop_front().expect("guarded nonempty"));}, Err(_)=>break }
                },
                permit=streams.reserve(), if !supplied_outbox.is_empty()=>{
                    match permit { Ok(permit)=>{permit.send(supplied_outbox.pop_front().expect("guarded nonempty"));}, Err(_)=>break }
                },
                effect=effects.recv()=>{
                    let Some(effect)=effect else{break;};
                    match effect {
                        Effect::PeerConnected(token,peer)=>{actions.extend(coordinator.connected(peer.clone(),origin.elapsed()));if notifications.send(Notification::Node(Effect::PeerConnected(token,peer))).await.is_err(){break;}}
                        Effect::PeerDisconnected(key)=>{actions.extend(coordinator.disconnected(key));if notifications.send(Notification::Node(Effect::PeerDisconnected(key))).await.is_err(){break;}}
                        Effect::PublicAddressDiscovered(address)=>{public_host=Some(address.host.clone());if notifications.send(Notification::Node(Effect::PublicAddressDiscovered(address))).await.is_err(){break;}}
                        Effect::Deliver(token,peer,Message::PeerMessage{topic,payload}) if topic==TOPIC=>{actions.extend(coordinator.signalled(&peer,&payload,origin.elapsed()));queue_node(&mut node_outbox,Event::Delivered(token))?;}
                        Effect::Completed(id,result)=>{
                            match pending.remove(&id){
                                Some(Pending::User(external_id))=>{if external.get(&external_id)==Some(&id) { external.remove(&external_id); }
                                if notifications.send(Notification::Node(Effect::Completed(external_id,result))).await.is_err(){break;}}
                                Some(Pending::Signal{ticket,peer,signal,waiting})=>match (waiting,result){
                                    (false,RequestResult::Backpressured)=>{request!(Pending::Signal{ticket,peer:peer.clone(),signal,waiting:true},Request::WaitUntilWritable{peer:peer.key,session_id:Some(peer.session_id)});}
                                    (true,RequestResult::Writable(true))=>actions.push_back(Action::Send{ticket,peer,signal}),
                                    (false,RequestResult::Enqueued)=>{if let Some(dial)=deferred_dials.remove(&ticket){actions.push_back(dial);}},
                                    _=>actions.extend(coordinator.failed(ticket,&peer)),
                                },
                                Some(Pending::Connect{ticket,peer}) if result!=RequestResult::Connected=>{actions.extend(coordinator.failed(ticket,&peer));},
                                Some(Pending::Connect{..})=>{},
                                Some(Pending::Internal)|None=>{},
                            }
                        }
                        other=>if notifications.send(Notification::Node(other)).await.is_err(){break;},
                    }
                },
                result=tasks.join_next(),if !tasks.is_empty()=>{
                    match result {
                        Some(Ok(WorkResult::Prepared { ticket, peer, attempt })) => {
                            handles.remove(&ticket);
                            match attempt {
                                Ok(attempt) => {
                                    let updates = coordinator.prepared(ticket, &peer, attempt.candidates(), origin.elapsed());
                                    if !updates.is_empty() { sockets.insert(ticket, attempt); actions.extend(updates); }
                                }
                                Err(_) => actions.extend(coordinator.failed(ticket, &peer)),
                            }
                        }
                        Some(Ok(WorkResult::Dial(DialResult { ticket, peer, initiator, stream }))) => {
                            handles.remove(&ticket);
                            let updates=coordinator.dial_finished(ticket,&peer,stream.is_ok());
                            if updates.is_empty(){continue;}
                            actions.extend(updates);
                            if let Ok(PunchedStream { stream, observed_host, local_host }) = stream {
                                let direction=if initiator {
                                    next=next.checked_add(1).ok_or_else(||io::Error::other("request IDs exhausted"))?;pending.insert(next,Pending::Connect{ticket,peer:peer.clone()});
                                    SuppliedDirection::ConnectWithLocal{request:next,local_host:local_host.clone(),endpoint:PeerEndpoint{public_key:peer.key.hex(),host:observed_host.clone().unwrap_or_default(),port:0}}
                                }else{SuppliedDirection::InboundWithLocal{local_host}};
                                supplied_outbox.push_back(SuppliedStream{stream,direction,observed_host});
                            }
                        }
                        _ => {}
                    }
                },
                _=async{match coordinator.next_deadline(){Some(at)=>tokio::time::sleep_until(origin+at).await,None=>std::future::pending::<()>().await}}=>actions.extend(coordinator.tick(origin.elapsed())),
                result=node.join_next()=>{return match result{Some(Ok(result))=>result,Some(Err(error))=>Err(io::Error::other(error)),None=>Ok(())};}
            }
        }
        Ok(())
    };
    let result = tokio::select! {
        result=coordinate=>result,
        _=shutdown=>Ok(()),
        _=notifications.closed()=>Ok(()),
    };
    coordinator.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(sockets);
    let _ = stop_node.send(());
    if node.is_empty() {
        return result;
    }
    // Drain shutdown effects so a full application channel cannot hold the node.
    loop {
        tokio::select! {_ = effects.recv()=>{},joined=node.join_next()=>return result.and(match joined{Some(Ok(result))=>result,Some(Err(error))=>Err(io::Error::other(error)),None=>Ok(())})}
    }
}

/// Native application policy matching Lattice's relay handling: attempt a
/// direct upgrade for each relayed endpoint and disconnect that exact session
/// if upgrade fails. Punch signalling is consumed internally; application
/// request IDs, deliveries, supplied streams and ledger remain unchanged.
/// Shutdown interrupts all bounded-channel waits and joins owned tasks.
#[allow(clippy::too_many_arguments)]
pub async fn run_application_with_shutdown(
    listener: TcpListener,
    config: Config,
    core: CoreSettings,
    mut commands: mpsc::Receiver<Event>,
    notifications: mpsc::Sender<Effect>,
    supplied: Option<mpsc::Receiver<SuppliedStream>>,
    ledger: impl ivy_core::PeerLedger + 'static,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    let (send, receive) = mpsc::channel(128);
    let (output, mut effects) = mpsc::channel(128);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut node = tokio::spawn(run_coordinator(
        listener,
        Settings {
            config,
            core,
            punch: Options::default(),
            hosts: None,
        },
        receive,
        output,
        ledger,
        TcpPunchTransport,
        supplied,
        async move {
            let _ = stopped.await;
        },
        true,
    ));
    let mut pumps = JoinSet::new();
    pumps.spawn(async move {
        while let Some(command) = commands.recv().await {
            if send.send(Command::Node(command)).await.is_err() {
                break;
            }
        }
    });
    pumps.spawn(async move {
        while let Some(effect) = effects.recv().await {
            if let Notification::Node(effect) = effect {
                if notifications.send(effect).await.is_err() {
                    break;
                }
            }
        }
    });
    let result = tokio::select! {
        joined=&mut node=>Some(joined),
        _=pumps.join_next()=>None,
        _=shutdown=>None,
    };
    let _ = stop.send(());
    pumps.abort_all();
    while pumps.join_next().await.is_some() {}
    let joined = match result {
        Some(joined) => joined,
        None => node.await,
    };
    joined.map_err(io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivy_core::core::AuthenticatedRoute;
    use std::time::Duration;
    struct TestTransport {
        custom: bool,
        fail: bool,
    }
    struct TestAttempt {
        inner: Box<dyn PreparedPunch>,
        custom: bool,
    }
    impl PunchTransport for TestTransport {
        fn prepare(
            &self,
            hosts: Vec<String>,
        ) -> crate::punch_transport::TransportFuture<'_, Box<dyn PreparedPunch>> {
            Box::pin(async move {
                if self.fail {
                    return Err(io::Error::other("test transport unavailable"));
                }
                let inner = TcpPunchTransport.prepare(hosts).await?;
                Ok(Box::new(TestAttempt {
                    inner,
                    custom: self.custom,
                }) as Box<dyn PreparedPunch>)
            })
        }
    }
    impl PreparedPunch for TestAttempt {
        fn candidates(&self) -> Vec<ivy_core::punch::Candidate> {
            let mut candidates = self.inner.candidates();
            if self.custom {
                for candidate in &mut candidates {
                    candidate.transport = 77;
                }
            }
            candidates
        }
        fn connect(
            self: Box<Self>,
            mut candidates: Vec<ivy_core::punch::Candidate>,
            private: bool,
            deadline: Instant,
        ) -> crate::punch_transport::TransportFuture<'static, PunchedStream> {
            // A test transport uses a distinct negotiated kind but wraps TCP;
            // this is not an implementation of QUIC or another wire protocol.
            if self.custom {
                for candidate in &mut candidates {
                    assert_eq!(candidate.transport, 77);
                    candidate.transport = ivy_core::punch::Candidate::TCP;
                }
            }
            self.inner.connect(candidates, private, deadline)
        }
    }
    #[tokio::test]
    async fn native_nodes_upgrade_relay_and_exchange_application_payload() {
        upgrade_nodes(false, false).await;
    }
    #[tokio::test]
    async fn custom_transport_upgrades_relay_and_authenticates_supplied_stream() {
        upgrade_nodes(true, false).await;
    }
    #[tokio::test]
    async fn application_policy_disconnects_failed_relay_upgrade_without_dropping_carrier() {
        upgrade_nodes(false, true).await;
    }
    async fn upgrade_nodes(custom: bool, fail: bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let configs: Vec<_> = (81..84)
                .map(|n| Config::new(ed25519_dalek::SigningKey::from_bytes(&[n; 32])))
                .collect();
            let keys: Vec<_> = configs.iter().map(Config::peer_key).collect();
            let mut configs = configs.into_iter();
            let carrier_config = configs.next().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (carrier_tx, carrier_rx) = mpsc::channel(128);
            let (carrier_notifications, mut carrier_effects) = mpsc::channel(128);
            let carrier = tokio::spawn(crate::node::run(
                listener,
                carrier_config,
                CoreSettings {
                    relay_enabled: true,
                    ..CoreSettings::default()
                },
                carrier_rx,
                carrier_notifications,
            ));
            let carrier_ack = carrier_tx.clone();
            let drain = tokio::spawn(async move {
                while let Some(effect) = carrier_effects.recv().await {
                    if let Effect::PeerConnected(token, _) | Effect::Deliver(token, _, _) = effect {
                        let _ = carrier_ack.send(Event::Delivered(token)).await;
                    }
                }
            });
            let mut commands = vec![];
            let mut tasks = vec![];
            let (events, mut incoming) = mpsc::channel(128);
            let mut pumps = vec![];
            for (index, config) in configs.enumerate() {
                let (tx, rx) = mpsc::channel(128);
                let (out, mut effects) = mpsc::channel(128);
                tasks.push(tokio::spawn(run_coordinator(
                    TcpListener::bind("127.0.0.1:0").await.unwrap(),
                    Settings {
                        config,
                        core: CoreSettings::default(),
                        punch: Options {
                            allow_private_candidates: true,
                            transports: vec![if custom {
                                77
                            } else {
                                ivy_core::punch::Candidate::TCP
                            }],
                            ..Options::default()
                        },
                        hosts: Some(vec!["127.0.0.1".into()]),
                    },
                    rx,
                    out,
                    ivy_core::NullLedger,
                    TestTransport { custom, fail },
                    None,
                    std::future::pending(),
                    true,
                )));
                let events = events.clone();
                let ack = tx.clone();
                pumps.push(tokio::spawn(async move {
                    while let Some(effect) = effects.recv().await {
                        if let Notification::Node(
                            Effect::PeerConnected(token, _) | Effect::Deliver(token, _, _),
                        ) = &effect
                        {
                            let _ = ack.send(Command::Node(Event::Delivered(*token))).await;
                        }
                        if events.send((index, effect)).await.is_err() {
                            break;
                        }
                    }
                }));
                tx.send(Command::Node(Event::Request(
                    1,
                    Request::Connect(PeerEndpoint {
                        public_key: keys[0].hex(),
                        host: "127.0.0.1".into(),
                        port: address.port(),
                    }),
                )))
                .await
                .unwrap();
                commands.push(tx);
            }
            let mut carriers = [None, None];
            let mut started = false;
            let mut direct = [false; 2];
            let mut sent = false;
            let mut completions = [false; 2];
            let mut disconnected = [false; 2];
            let mut relayed = [false; 2];
            loop {
                let (index, event) = incoming.recv().await.unwrap();
                match event {
                    Notification::Node(Effect::PeerConnected(_, peer)) => {
                        if peer.key == keys[0] {
                            carriers[index] = Some(peer);
                        } else if peer.route == AuthenticatedRoute::Direct {
                            direct[index] = true;
                        } else {
                            relayed[index] = true;
                        }
                    }
                    Notification::Node(Effect::PeerDisconnected(key)) if fail => {
                        assert_ne!(key, keys[0], "carrier must remain connected");
                        assert_eq!(key, keys[2 - index]);
                        disconnected[index] = true;
                        if disconnected.iter().all(|value| *value) {
                            break;
                        }
                    }
                    Notification::Node(Effect::Completed(1, RequestResult::Connected)) => {
                        completions[index] = true
                    }
                    Notification::Node(Effect::Deliver(
                        _,
                        peer,
                        Message::PeerMessage { topic, payload },
                    )) => {
                        assert_eq!(index, 1);
                        assert_eq!(peer.route, AuthenticatedRoute::Direct);
                        assert_eq!(topic, "after-punch");
                        assert_eq!(payload, vec![7; 200_000]);
                        break;
                    }
                    _ => {}
                }
                if !started && carriers.iter().all(Option::is_some) {
                    started = true;
                    commands[0]
                        .send(Command::Node(Event::Request(
                            2,
                            Request::ConnectViaRelay {
                                carrier: carriers[0].clone().unwrap(),
                                target: keys[2],
                            },
                        )))
                        .await
                        .unwrap();
                }
                if !sent && direct.iter().all(|d| *d) {
                    sent = true;
                    commands[0]
                        .send(Command::Node(Event::Request(
                            3,
                            Request::Send {
                                peer: keys[2],
                                session_id: None,
                                message: Message::PeerMessage {
                                    topic: "after-punch".into(),
                                    payload: vec![7; 200_000],
                                },
                            },
                        )))
                        .await
                        .unwrap();
                }
            }
            assert!(completions.iter().all(|c| *c));
            if fail {
                assert!(relayed.iter().all(|value| *value));
                assert!(!direct.iter().any(|value| *value));
            }
            for tx in &commands {
                tx.send(Command::Node(Event::Stop)).await.unwrap();
            }
            for task in tasks {
                task.await.unwrap().unwrap();
            }
            carrier_tx.send(Event::Stop).await.unwrap();
            carrier.await.unwrap().unwrap();
            drain.await.unwrap();
            for pump in pumps {
                pump.await.unwrap();
            }
        })
        .await
        .expect("automatic relay upgrade timed out");
    }
}

#[cfg(test)]
mod application_tests;
