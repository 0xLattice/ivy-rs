use ivy_core::{
    core::{CoreSettings as Settings, Effect, Event, Request},
    Config, PeerEndpoint,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn continuous_request_progress_probe() {
    let (send, commands) = mpsc::channel(4096);
    let (notifications, mut effects) = mpsc::channel(4096);
    let (stop, shutdown) = oneshot::channel();
    let mut settings = Settings::default();
    settings.stun_servers.clear();
    let node = tokio::spawn(ivy::punch_node::run_application_with_shutdown(
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        Config::new(ed25519_dalek::SigningKey::from_bytes(&[71; 32])),
        settings,
        commands,
        notifications,
        None,
        ivy_core::NullLedger,
        async {
            let _ = shutdown.await;
        },
    ));
    let sent = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let a = sent.clone();
    let b = completed.clone();
    let producer = tokio::spawn(async move {
        for id in 0..20_000 {
            send.send(Event::Request(
                id,
                Request::Connect(PeerEndpoint {
                    public_key: "invalid".into(),
                    host: "127.0.0.1".into(),
                    port: 1,
                }),
            ))
            .await
            .unwrap();
            a.fetch_add(1, Ordering::Relaxed);
        }
        send
    });
    let consumer = tokio::spawn(async move {
        while let Some(effect) = effects.recv().await {
            if matches!(effect, Effect::Completed(..)) {
                b.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let mut previous = 0;
    let mut stalled = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let done = completed.load(Ordering::Relaxed);
        let total = sent.load(Ordering::Relaxed);
        if done == 20_000 {
            break;
        }
        if done == previous && total > done {
            stalled = true;
            break;
        }
        previous = done;
    }
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), node)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    if !stalled {
        let sender = tokio::time::timeout(Duration::from_secs(5), producer)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
        consumer.await.unwrap();
    } else {
        producer.abort();
        consumer.abort();
    }
    assert!(
        !stalled
            && sent.load(Ordering::Relaxed) == 20_000
            && completed.load(Ordering::Relaxed) == 20_000,
        "coordinator stopped progressing while the application continuously drained effects"
    );
}
