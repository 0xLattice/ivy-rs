//! Tokio TCP shell for the deterministic Ivy core. Consume notifications and
//! acknowledge `PeerConnected`/`Deliver` with `Event::Delivered` to resume reads.
//! Commands and notifications are bounded channels supplied by the caller.
use ivy_core::core::{ConnectionDirection, Core, CoreSettings, Effect, Event, Timestamp};
use ivy_core::Config;
use rand_core::OsRng;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::Instant,
};
/// An ordered, bidirectional stream (TCP, WebSocket, a supplied punch socket).
pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportStream for T {}
pub enum SuppliedDirection {
    InboundWithLocal {
        local_host: Option<String>,
    },
    ConnectWithLocal {
        request: u64,
        endpoint: ivy_core::PeerEndpoint,
        local_host: Option<String>,
    },
    Inbound,
    Connect {
        request: u64,
        endpoint: ivy_core::PeerEndpoint,
    },
}
pub struct SuppliedStream {
    pub stream: Box<dyn TransportStream>,
    pub direction: SuppliedDirection,
    pub observed_host: Option<String>,
}
enum Control {
    Write(u64, Vec<u8>),
    Reading(bool),
    Close,
}
enum TransportEvent {
    Opened(TcpStream, ConnectionDirection, String),
    Core(Event),
    Flushed(u64, u64),
}
/// Runs a TCP node until `Stop` or the command channel closes. Time, socket
/// readiness and entropy are translated into core inputs. Socket tasks are
/// cancelled and awaited before returning. The listener's address should match
/// the listen metadata supplied in `config`.
pub async fn run(
    listener: TcpListener,
    config: Config,
    settings: CoreSettings,
    commands: mpsc::Receiver<Event>,
    notifications: mpsc::Sender<Effect>,
) -> io::Result<()> {
    run_with_ledger(
        listener,
        config,
        settings,
        commands,
        notifications,
        ivy_core::NullLedger,
    )
    .await
}

/// Runs with a shared peer ledger, such as `ivy_tally::TallyLedger`.
pub async fn run_with_ledger(
    listener: TcpListener,
    config: Config,
    settings: CoreSettings,
    commands: mpsc::Receiver<Event>,
    notifications: mpsc::Sender<Effect>,
    ledger: impl ivy_core::PeerLedger + 'static,
) -> io::Result<()> {
    run_with_supplied(
        listener,
        config,
        settings,
        commands,
        notifications,
        None,
        ledger,
    )
    .await
}

/// Runs the same core with an optional bounded channel for externally opened
/// streams. Outbound supplied streams retain caller request IDs and authenticate
/// the expected endpoint before they replace a relayed session.
pub async fn run_with_supplied(
    listener: TcpListener,
    config: Config,
    settings: CoreSettings,
    commands: mpsc::Receiver<Event>,
    notifications: mpsc::Sender<Effect>,
    supplied: Option<mpsc::Receiver<SuppliedStream>>,
    ledger: impl ivy_core::PeerLedger + 'static,
) -> io::Result<()> {
    run_with_shutdown(
        listener,
        config,
        settings,
        commands,
        notifications,
        supplied,
        ledger,
        std::future::pending(),
    )
    .await
}

/// Out-of-band shutdown remains responsive even if notification delivery is
/// backpressured. Resolving `shutdown` closes and awaits all owned transport
/// tasks. Shutdown notifications are best effort; applications must cancel their
/// own content jobs when stopping rather than rely on a final CancelJob event.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_shutdown(
    listener: TcpListener,
    config: Config,
    settings: CoreSettings,
    mut commands: mpsc::Receiver<Event>,
    notifications: mpsc::Sender<Effect>,
    mut supplied: Option<mpsc::Receiver<SuppliedStream>>,
    ledger: impl ivy_core::PeerLedger + 'static,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let mut settings = settings;
    if settings.listen_port.is_none() && config.metadata.listen_addresses.is_empty() {
        settings.listen_port = Some(listener.local_addr()?.port());
    }
    settings
        .validate(&config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let stun_servers = settings.stun_servers.clone();
    let mut core = Core::new(&config, settings, OsRng).with_ledger(ledger);
    let origin = Instant::now();
    let (events_tx, mut events_rx) = mpsc::channel::<TransportEvent>(256);
    let mut tasks = JoinSet::new();
    let mut dials: BTreeMap<u64, tokio::task::AbortHandle> = BTreeMap::new();
    let mut connections: BTreeMap<u64, (mpsc::UnboundedSender<Control>, u64)> = BTreeMap::new();
    let mut next_connection = 0u64;
    let mut wake: Option<Instant> = None;
    let mut pending = Some(Event::Start);
    loop {
        let event = if let Some(event) = pending.take() {
            event
        } else {
            tokio::select! {
                _=&mut shutdown=>Event::Stop,
                command=commands.recv()=>command.unwrap_or(Event::Stop),
                incoming=async {match &mut supplied{Some(channel)=>channel.recv().await,None=>std::future::pending::<Option<SuppliedStream>>().await}}=>{
                    let Some(incoming)=incoming else{supplied=None;continue;};
                    next_connection=next_connection.checked_add(1).ok_or_else(||io::Error::other("connection IDs exhausted"))?;
                    let id=next_connection;let (tx,rx)=mpsc::unbounded_channel();connections.insert(id,(tx,0));tasks.spawn(connection_task(id,incoming.stream,rx,events_tx.clone()));
                    match incoming.direction {SuppliedDirection::InboundWithLocal{local_host}=>Event::ConnectionOpenedWithLocal{connection:id,direction:ConnectionDirection::Inbound,observed_host:incoming.observed_host,local_host},SuppliedDirection::ConnectWithLocal{request,endpoint,local_host}=>Event::Request(request,ivy_core::core::Request::ConnectOverWithLocal{endpoint,connection:id,observed_host:incoming.observed_host,local_host}),SuppliedDirection::Inbound=>Event::ConnectionOpened{connection:id,direction:ConnectionDirection::Inbound,observed_host:incoming.observed_host},SuppliedDirection::Connect{request,endpoint}=>Event::Request(request,ivy_core::core::Request::ConnectOver{endpoint,connection:id,observed_host:incoming.observed_host})}
                },
                transport=events_rx.recv()=>match transport {
                    Some(TransportEvent::Opened(stream,direction,host))=>{let local_host=stream.local_addr().ok().map(|a|a.ip().to_string());next_connection=next_connection.checked_add(1).ok_or_else(||io::Error::other("connection IDs exhausted"))?;let id=next_connection;let (tx,rx)=mpsc::unbounded_channel();connections.insert(id,(tx,0));tasks.spawn(connection_task(id,stream,rx,events_tx.clone()));Event::ConnectionOpenedWithLocal{connection:id,direction,observed_host:Some(host),local_host}},
                    Some(TransportEvent::Core(event))=>event,
                    Some(TransportEvent::Flushed(id,generation))=>{if connections.get(&id).is_some_and(|(_,current)|*current==generation){Event::Writable(id)}else{continue;}},
                    None=>Event::Stop,
                },
                accepted=listener.accept()=>{let (stream,address)=accepted?;let local_host=stream.local_addr().ok().map(|a|a.ip().to_string());next_connection=next_connection.checked_add(1).ok_or_else(||io::Error::other("connection IDs exhausted"))?;let id=next_connection;let (tx,rx)=mpsc::unbounded_channel();connections.insert(id,(tx,0));tasks.spawn(connection_task(id,stream,rx,events_tx.clone()));Event::ConnectionOpenedWithLocal{connection:id,direction:ConnectionDirection::Inbound,observed_host:Some(address.ip().to_string()),local_host}},
                _=async {match wake {Some(deadline)=>tokio::time::sleep_until(deadline).await,None=>std::future::pending::<()>().await}}=>{wake=None;Event::Tick},
                _=tasks.join_next(),if !tasks.is_empty()=>continue,
            }
        };
        let stopping = matches!(event, Event::Stop);
        if let Event::Closed(id) = &event {
            connections.remove(id);
        }
        let now = Timestamp {
            uptime: origin.elapsed(),
            unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        };
        for effect in core.step(event, now) {
            match effect {
                Effect::DiscoverPublicAddress => {
                    let servers = stun_servers.clone();
                    let tx = events_tx.clone();
                    tasks.spawn(async move {
                        let address = crate::stun::discover(&servers).await;
                        let _ = tx
                            .send(TransportEvent::Core(Event::PublicAddress(address)))
                            .await;
                    });
                }
                Effect::Dial(id, endpoint) => {
                    let tx = events_tx.clone();
                    let task = tasks.spawn(async move {
                        let event = match tokio::time::timeout(
                            Duration::from_secs(5),
                            TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                let host = stream
                                    .peer_addr()
                                    .map(|a| a.ip().to_string())
                                    .unwrap_or(endpoint.host);
                                TransportEvent::Opened(
                                    stream,
                                    ConnectionDirection::Outbound(id),
                                    host,
                                )
                            }
                            Ok(Err(_)) | Err(_) => TransportEvent::Core(Event::DialFailed(id)),
                        };
                        let _ = tx.send(event).await;
                    });
                    dials.insert(id, task);
                }
                Effect::Write(id, bytes) => {
                    if let Some((tx, generation)) = connections.get_mut(&id) {
                        *generation = generation.wrapping_add(1);
                        if tx.send(Control::Write(*generation, bytes)).is_err() {
                            pending = Some(Event::Closed(id));
                        }
                    }
                }
                Effect::Close(id) => {
                    if let Some((tx, _)) = connections.remove(&id) {
                        let _ = tx.send(Control::Close);
                    }
                }
                Effect::PauseReading(id) => {
                    if let Some((tx, _)) = connections.get(&id) {
                        let _ = tx.send(Control::Reading(false));
                    }
                }
                Effect::ResumeReading(id) => {
                    if let Some((tx, _)) = connections.get(&id) {
                        let _ = tx.send(Control::Reading(true));
                    }
                }
                Effect::WakeAt(deadline) => wake = Some(origin + deadline),
                notification => {
                    if stopping {
                        // Teardown must never depend on a consumer draining its
                        // bounded queue. Transport tasks are owned here; source
                        // jobs are owned by the application.
                        let _ = notifications.try_send(notification);
                    } else {
                        tokio::select! {
                            biased;
                            _=&mut shutdown=>{pending=Some(Event::Stop);break;},
                            result=notifications.send(notification)=>{
                                if result.is_err(){pending=Some(Event::Stop);break;}
                            }
                        }
                    }
                }
            }
        }
        let live_dials: std::collections::BTreeSet<_> = core.pending_dial_ids().collect();
        dials.retain(|id, handle| {
            if live_dials.contains(id) {
                true
            } else {
                handle.abort();
                false
            }
        });
        if stopping {
            break;
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn connection_task<S: TransportStream + 'static>(
    id: u64,
    stream: S,
    mut commands: mpsc::UnboundedReceiver<Control>,
    events: mpsc::Sender<TransportEvent>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut reading = false;
    let mut out: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut offset = 0;
    let mut flush_pending = None;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        tokio::select! {
            command=commands.recv()=>match command {Some(Control::Write(g,bytes))=>out.push_back((g,bytes)),Some(Control::Reading(wanted))=>reading=wanted,Some(Control::Close)|None=>break},
            read=reader.read(&mut buffer),if reading=>match read {Ok(0)|Err(_)=>break,Ok(n)=>{if events.send(TransportEvent::Core(Event::Received(id,buffer[..n].to_vec()))).await.is_err(){break;}}},
            written=async{if let Some((_,bytes))=out.front(){writer.write(&bytes[offset..]).await}else{writer.flush().await.map(|_|0)}},if !out.is_empty() || flush_pending.is_some()=>match written {
                Err(_)=>break,
                Ok(_) if out.is_empty()=>{if let Some(generation)=flush_pending.take(){if events.send(TransportEvent::Flushed(id,generation)).await.is_err(){break;}}},
                Ok(0)=>break,
                Ok(n)=>{offset+=n;if offset==out.front().unwrap().1.len(){let (generation,_)=out.pop_front().unwrap();offset=0;if out.is_empty(){flush_pending=Some(generation);}}}
            },
        }
    }
    let _ = events.send(TransportEvent::Core(Event::Closed(id))).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivy_core::core::{Request, RequestResult};
    use ivy_core::{ListenAddress, Message, PeerEndpoint};
    #[tokio::test]
    async fn shutdown_interrupts_full_notification_queue_and_closes_real_tcp() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut remote = TcpStream::connect(pair.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = pair.accept().await.unwrap();
            let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[31; 32]));
            let other = Config::new(ed25519_dalek::SigningKey::from_bytes(&[32; 32]));
            let endpoint = PeerEndpoint {
                public_key: other.peer_key().hex(),
                host: "127.0.0.1".into(),
                port: 1,
            };
            let (commands, receiver) = mpsc::channel(4);
            let (notifications, mut effects) = mpsc::channel(1);
            let (streams, supplied) = mpsc::channel(1);
            let (shutdown, cancelled) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(run_with_shutdown(
                listener,
                config,
                CoreSettings::default(),
                receiver,
                notifications,
                Some(supplied),
                ivy_core::NullLedger,
                async {
                    let _ = cancelled.await;
                },
            ));
            streams
                .send(SuppliedStream {
                    stream: Box::new(stream),
                    direction: SuppliedDirection::Connect {
                        request: 1,
                        endpoint,
                    },
                    observed_host: Some("127.0.0.1".into()),
                })
                .await
                .unwrap();
            let mut bytes = [0; 4096];
            assert!(
                remote.read(&mut bytes).await.unwrap() > 0,
                "owned TCP task wrote its handshake"
            );
            let invalid = PeerEndpoint {
                public_key: "invalid".into(),
                host: "127.0.0.1".into(),
                port: 1,
            };
            commands
                .send(Event::Request(2, Request::Connect(invalid.clone())))
                .await
                .unwrap();
            commands
                .send(Event::Request(3, Request::Connect(invalid)))
                .await
                .unwrap();
            while commands.capacity() != 4 || effects.len() != 1 {
                tokio::task::yield_now().await;
            }
            // Both requests were consumed; one completion occupies the queue
            // and the next is waiting for capacity. Do not drain it.
            shutdown.send(()).unwrap();
            task.await.unwrap().unwrap();
            remote.read_to_end(&mut Vec::new()).await.unwrap();
            assert!(effects.recv().await.is_some());
            assert!(
                effects.recv().await.is_none(),
                "sender and socket tasks are gone"
            );
        })
        .await
        .expect("out-of-band shutdown cannot deadlock on notifications");
    }

    #[tokio::test]
    async fn stop_does_not_block_on_its_own_completion_notifications() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[33; 32]));
            let (commands, receiver) = mpsc::channel(4);
            let (notifications, _effects) = mpsc::channel(1);
            notifications
                .send(Effect::Completed(99, RequestResult::Failed))
                .await
                .unwrap();
            let endpoint = PeerEndpoint {
                public_key: Config::new(ed25519_dalek::SigningKey::from_bytes(&[34; 32]))
                    .peer_key()
                    .hex(),
                host: "127.0.0.1".into(),
                port: destination.local_addr().unwrap().port(),
            };
            commands
                .send(Event::Request(1, Request::Connect(endpoint)))
                .await
                .unwrap();
            commands.send(Event::Stop).await.unwrap();
            run(
                listener,
                config,
                CoreSettings::default(),
                receiver,
                notifications,
            )
            .await
            .unwrap();
        })
        .await
        .expect("stop notifications are best effort, never a shutdown barrier");
    }

    #[tokio::test]
    async fn two_tcp_nodes_authenticate_deliver_and_stop_cleanly() {
        tokio::time::timeout(Duration::from_secs(10),async {
            let left=TcpListener::bind("127.0.0.1:0").await.unwrap();let right=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut a=Config::new(ed25519_dalek::SigningKey::from_bytes(&[1;32]));let mut b=Config::new(ed25519_dalek::SigningKey::from_bytes(&[2;32]));
            a.metadata.listen_addresses=vec![ListenAddress{host:"127.0.0.1".into(),port:left.local_addr().unwrap().port()}];b.metadata.listen_addresses=vec![ListenAddress{host:"127.0.0.1".into(),port:right.local_addr().unwrap().port()}];
            let endpoint=PeerEndpoint{public_key:b.peer_key().hex(),host:"127.0.0.1".into(),port:right.local_addr().unwrap().port()};let b_key=b.peer_key();
            let (a_tx,a_rx)=mpsc::channel(16);let (b_tx,b_rx)=mpsc::channel(16);let (a_out,mut a_events)=mpsc::channel(16);let (b_out,mut b_events)=mpsc::channel(16);
            let a_task=tokio::spawn(run(left,a,CoreSettings::default(),a_rx,a_out));let b_task=tokio::spawn(run(right,b,CoreSettings::default(),b_rx,b_out));
            a_tx.send(Event::Request(1,Request::Connect(endpoint))).await.unwrap();
            let mut a_connected=false;let mut b_connected=false;let mut completed=false;
            while !(a_connected&&b_connected&&completed) {tokio::select! {
                e=a_events.recv()=>match e.unwrap(){Effect::PeerConnected(token,_)=>{a_connected=true;a_tx.send(Event::Delivered(token)).await.unwrap();},Effect::Completed(1,RequestResult::Connected)=>completed=true,e=>panic!("unexpected {e:?}")},
                e=b_events.recv()=>match e.unwrap(){Effect::PeerConnected(token,_)=>{b_connected=true;b_tx.send(Event::Delivered(token)).await.unwrap();},e=>panic!("unexpected {e:?}")},
            }}
            let message=Message::PeerMessage{topic:"node".into(),payload:vec![42;100000]};a_tx.send(Event::Request(2,Request::Send{peer:b_key,session_id:None,message:message.clone()})).await.unwrap();
            match b_events.recv().await.unwrap(){Effect::Deliver(token,_,received)=>{assert_eq!(message,received);b_tx.send(Event::Delivered(token)).await.unwrap();},e=>panic!("unexpected {e:?}")}
            a_tx.send(Event::Stop).await.unwrap();b_tx.send(Event::Stop).await.unwrap();a_task.await.unwrap().unwrap();b_task.await.unwrap().unwrap();
        }).await.expect("TCP nodes make progress");
    }
}
