use neli::neli_enum;

pub const FAMILY_NAME: &str = "ksec";

#[neli_enum(serialized_type = "u8")]
pub enum KsecCommand {
    Unspec = 0,
    CheckHiddenModules = 1,
    CheckSyscalls = 2,
    CheckInterrupts = 3,
    CheckFops = 4,
}
impl neli::consts::genl::Cmd for KsecCommand {}

#[neli_enum(serialized_type = "u16")]
pub enum KsecAttribute {
    Unspec = 0,
    Msg = 1,
}
impl neli::consts::genl::NlAttrType for KsecAttribute {}

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};
use std::process;
use std::env;

fn send_netlink_message(msg: String, cmd: KsecCommand) -> Option<String> {
    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic,
        Some(0),
        &[],
    )
    .unwrap();

    let family_id;
    let res = sock.resolve_genl_family(FAMILY_NAME);
    match res {
        Ok(id) => family_id = id,
        Err(e) => {
            eprintln!(
                "netlink family '{}' not found, error='{:#?}'",
                FAMILY_NAME, e
            );
            return None;
        }
    }

    let mut attrs: GenlBuffer<KsecAttribute, Buffer> = GenlBuffer::new();
    attrs.push(
        Nlattr::new(
            false,
            false,
            KsecAttribute::Msg,
            msg,
        )
        .unwrap(),
    );

    let gnmsghdr = Genlmsghdr::new(
        cmd,
        1,
        attrs,
    );

    let nlmsghdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        Some(process::id()),
        NlPayload::Payload(gnmsghdr),
    );

    sock.send(nlmsghdr).expect("Failed to send");

    let res: Nlmsghdr<u16, Genlmsghdr<KsecCommand, KsecAttribute>> =
        sock.recv().expect("Didn't receive a message").unwrap();

    let attr_handle = res.get_payload().unwrap().get_attr_handle();
    let received = attr_handle
        .get_attr_payload_as_with_len::<String>(KsecAttribute::Msg)
        .unwrap();

    return Some(received);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let cmd: KsecCommand;

    cmd = match args[1].as_str() {
        "checkFops" => KsecCommand::CheckFops,
        "checkHiddenModules" => KsecCommand::CheckHiddenModules,
        "checkInterrupts" => KsecCommand::CheckInterrupts,
        "checkSyscalls" => KsecCommand::CheckSyscalls,
        _ => KsecCommand::CheckHiddenModules,
    };

    let result = send_netlink_message(String::from(""), cmd);

    println!("{}", result.unwrap());

    return;
}

