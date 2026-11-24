//! CVP-017/019 interoperability of distinct application adapters.
//!
//! This is a provider-neutral shared-Rust-library and in-memory network
//! reference test, NOT an independent third-party HTTP implementation or
//! proof that Commonveil's deployed backend speaks public CVP-019.
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

/// A chat product, which knows nothing about Secure Net's implementation
/// internals except its public client operations.
struct AuroraChat {
    account: SocialClient,
}
impl AuroraChat {
    fn join(net: &mut MemoryNetwork) -> Self {
        let mut client =
            SocialClient::new("alexa@aurora.example", "Person", None, 2, true, NOW).unwrap();
        client.register(net).unwrap();
        Self { account: client }
    }
    fn address_book_lookup(&mut self, net: &mut MemoryNetwork, handle: &str) {
        self.account.lookup(net, handle).unwrap();
    }
    fn send_dm(&mut self, net: &mut MemoryNetwork, peer: &str, text: &str) {
        self.account.post(net, text, &json!([peer])).unwrap();
    }
    fn inbox(&mut self, net: &mut MemoryNetwork) -> Vec<Value> {
        self.account.sync(net).unwrap()
    }
}

/// A project-notes product with its own UI and data model. It only exchanges
/// CVP encrypted messages with the chat product via the shared protocol.
struct LanternNotes {
    account: SocialClient,
}
impl LanternNotes {
    fn join(net: &mut MemoryNetwork) -> Self {
        let mut client =
            SocialClient::new("ben@lantern.example", "Person", None, 2, true, NOW).unwrap();
        client.register(net).unwrap();
        Self { account: client }
    }
    fn discover_actor(&mut self, net: &mut MemoryNetwork, handle: &str) {
        self.account.lookup(net, handle).unwrap();
    }
    fn share_private_note(&mut self, net: &mut MemoryNetwork, actor: &str, note: &str) {
        self.account.post(net, note, &json!([actor])).unwrap();
    }
    fn receive_private_notes(&mut self, net: &mut MemoryNetwork) -> Vec<Value> {
        self.account.sync(net).unwrap()
    }
}

fn network() -> MemoryNetwork {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("aurora.example").unwrap());
    net.add(ReferenceSite::new("lantern.example").unwrap());
    net
}

#[test]
fn independent_app_adapters_exchange_encrypted_messages_without_commonveil_accounts() {
    let mut net = network();
    let mut chat = AuroraChat::join(&mut net);
    let mut notes = LanternNotes::join(&mut net);
    chat.address_book_lookup(&mut net, "ben@lantern.example");
    notes.discover_actor(&mut net, "alexa@aurora.example");

    let chat_actor_id = chat.account.id.clone();
    let notes_actor_id = notes.account.id.clone();
    let first_secret = "AURORA PRIVATE CHAT V5";
    chat.send_dm(&mut net, &notes_actor_id, first_secret);

    // Both clients operate on separate applications' mailboxes.
    let mut incoming = Vec::new();
    for _ in 0..4 {
        incoming.extend(notes.receive_private_notes(&mut net));
        chat.inbox(&mut net);
    }
    assert!(incoming
        .iter()
        .any(|e| e["content"] == first_secret && e["how"] == "direct"));
    let answer = "LANTERN PRIVATE NOTE V3";
    notes.share_private_note(&mut net, &chat_actor_id, answer);
    let mut received = Vec::new();
    for _ in 0..4 {
        received.extend(chat.inbox(&mut net));
        notes.receive_private_notes(&mut net);
    }
    assert!(received
        .iter()
        .any(|e| e["content"] == answer && e["how"] == "direct"));

    let public_log = net.log.join("\n");
    assert!(
        !public_log.contains(first_secret),
        "first private message must not be present in relay logging"
    );
    assert!(
        !public_log.contains(answer),
        "reply must not be present in relay logging"
    );
    assert!(net.site("aurora.example").unwrap().document()["endpoints"]["outbox"].is_string());
    assert!(net.site("lantern.example").unwrap().document()["endpoints"]["mailbox"].is_string());
    assert_eq!(
        net.site("aurora.example").unwrap().document()["protocol"],
        "secure-net"
    );
    assert_eq!(
        net.site("lantern.example").unwrap().document()["features"]["cvp.delivery"],
        2
    );
}

#[test]
fn other_apps_cannot_advertise_commonveil_internal_urls_as_a_replacement_for_cvp_delivery() {
    let net = network();
    let doc = net.sites["aurora.example"].document();
    assert_eq!(doc["endpoints"]["outbox"], "/cvp/v2/outbox");
    assert_eq!(doc["endpoints"]["deliver"], "/cvp/v2/deliver");
    assert_eq!(doc["endpoints"]["mailbox"], "/cvp/v2/mailbox");
    assert_ne!(doc["endpoints"]["outbox"], "/cvp/v1/act");
    assert_ne!(doc["endpoints"]["mailbox"], "/cvp/v1/inbox");
}

#[test]
fn rejected_site_deliveries_do_not_create_recipient_mailbox_items() {
    use secure_net_core::social::delivery::delivery_body;
    use secure_net_core::wire::federation::{digest_of, sign_request, RequestFields};
    let mut net = network();
    let notes = LanternNotes::join(&mut net);
    let site = net.site("aurora.example").unwrap();
    let secret_key = site.secret_key.clone();
    let empty = json!([]);
    // Zero-item remote delivery fails at the shared strict envelope boundary.
    assert!(delivery_body(&[]).is_err());
    // A correctly signed but invalid zero-item delivery fails atomically.
    let date = secure_net_core::cv::encoding::iso_from_ms(NOW).unwrap();
    let nonce = "not-the-original-nonce-01";
    let digest = digest_of(empty.to_string().as_bytes());
    let fields = RequestFields {
        method: "POST",
        to: "lantern.example",
        path: "/cvp/v2/deliver",
        from: "aurora.example",
        date: &date,
        nonce,
        digest: &digest,
        user: "",
    };
    let payload = json!({
        "method": "POST", "to": "lantern.example", "path": "/cvp/v2/deliver",
        "from": "aurora.example", "date": date, "nonce": nonce, "digest": digest,
        "signature": sign_request(&fields, &secret_key).unwrap(),
        "body": empty.to_string()
    });
    let before = net.site("lantern.example").unwrap().mailboxes[&notes.account.id].len();
    assert!(net.receive("lantern.example", &payload, NOW).is_err());
    assert_eq!(
        net.site("lantern.example").unwrap().mailboxes[&notes.account.id].len(),
        before
    );

    // A forged sender label cannot turn Aurora's real site signature into
    // Lantern's signature. Different application implementations must not
    // trust claims made by another site's arbitrary transport JSON.
    let mut forged = payload.clone();
    forged["from"] = json!("lantern.example");
    forged["nonce"] = json!("independent-forgery-nonce");
    assert_eq!(
        net.receive("lantern.example", &forged, NOW)
            .unwrap_err()
            .code,
        "UNTRUSTED"
    );
    assert_eq!(
        net.site("lantern.example").unwrap().mailboxes[&notes.account.id].len(),
        before
    );
}
