//! HFP service facade

use bt_topshim::btif::{BluetoothInterface, RawAddress};
use bt_topshim::profiles::hfp::{Hfp, HfpCallbacksDispatcher};
use bt_topshim_facade_protobuf::empty::Empty;
use bt_topshim_facade_protobuf::facade::{
    ConnectAudioRequest, DisconnectAudioRequest, SetVolumeRequest, StartSlcRequest, StopSlcRequest,
};
use bt_topshim_facade_protobuf::facade_grpc::{create_hfp_service, HfpService};

use grpcio::*;

use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

fn get_hfp_dispatcher() -> HfpCallbacksDispatcher {
    HfpCallbacksDispatcher { dispatch: Box::new(move |_cb| {}) }
}

/// Main object for Hfp facade service
#[derive(Clone)]
pub struct HfpServiceImpl {
    #[allow(dead_code)]
    rt: Arc<Runtime>,
    pub btif_hfp: Arc<Mutex<Hfp>>,
}

impl HfpServiceImpl {
    /// Create a new instance of the root facade service
    pub fn create(rt: Arc<Runtime>, btif_intf: Arc<Mutex<BluetoothInterface>>) -> grpcio::Service {
        let mut btif_hfp = Hfp::new(&btif_intf.lock().unwrap());
        btif_hfp.initialize(get_hfp_dispatcher());

        create_hfp_service(Self { rt, btif_hfp: Arc::new(Mutex::new(btif_hfp)) })
    }
}

impl HfpService for HfpServiceImpl {
    fn start_slc(&mut self, ctx: RpcContext<'_>, req: StartSlcRequest, sink: UnarySink<Empty>) {
        let hfp = self.btif_hfp.clone();
        ctx.spawn(async move {
            let bt_addr = &req.connection.unwrap().cookie;
            if let Some(addr) = RawAddress::from_bytes(bt_addr) {
                hfp.lock().unwrap().connect(addr);
                sink.success(Empty::default()).await.unwrap();
            } else {
                sink.fail(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("Invalid Request Address: {}", from_utf8(bt_addr).unwrap()),
                ))
                .await
                .unwrap();
            }
        })
    }

    fn stop_slc(&mut self, ctx: RpcContext<'_>, req: StopSlcRequest, sink: UnarySink<Empty>) {
        let hfp = self.btif_hfp.clone();
        ctx.spawn(async move {
            let bt_addr = &req.connection.unwrap().cookie;
            if let Some(addr) = RawAddress::from_bytes(bt_addr) {
                hfp.lock().unwrap().disconnect(addr);
                sink.success(Empty::default()).await.unwrap();
            } else {
                sink.fail(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("Invalid Request Address: {}", from_utf8(bt_addr).unwrap()),
                ))
                .await
                .unwrap();
            }
        })
    }

    fn connect_audio(
        &mut self,
        ctx: RpcContext<'_>,
        req: ConnectAudioRequest,
        sink: UnarySink<Empty>,
    ) {
        let hfp = self.btif_hfp.clone();
        ctx.spawn(async move {
            let bt_addr = &req.connection.unwrap().cookie;
            if let Some(addr) = RawAddress::from_bytes(bt_addr) {
                hfp.lock().unwrap().connect_audio(addr, req.is_sco_offload_enabled, req.force_cvsd);
                hfp.lock().unwrap().set_active_device(addr);
                sink.success(Empty::default()).await.unwrap();
            } else {
                sink.fail(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("Invalid Request Address: {}", from_utf8(bt_addr).unwrap()),
                ))
                .await
                .unwrap();
            }
        })
    }

    fn disconnect_audio(
        &mut self,
        ctx: RpcContext<'_>,
        req: DisconnectAudioRequest,
        sink: UnarySink<Empty>,
    ) {
        let hfp = self.btif_hfp.clone();
        ctx.spawn(async move {
            let bt_addr = &req.connection.unwrap().cookie;
            if let Some(addr) = RawAddress::from_bytes(bt_addr) {
                hfp.lock().unwrap().disconnect_audio(addr);
                sink.success(Empty::default()).await.unwrap();
            } else {
                sink.fail(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("Invalid Request Address: {}", from_utf8(bt_addr).unwrap()),
                ))
                .await
                .unwrap();
            }
        })
    }

    fn set_volume(&mut self, ctx: RpcContext<'_>, req: SetVolumeRequest, sink: UnarySink<Empty>) {
        let hfp = self.btif_hfp.clone();
        ctx.spawn(async move {
            let bt_addr = &req.connection.unwrap().cookie;
            if let Some(addr) = RawAddress::from_bytes(bt_addr) {
                // TODO(aritrasen): Consider using TryFrom and cap the maximum volume here
                // since `as` silently deals with data overflow, which might not be preferred.
                hfp.lock().unwrap().set_volume(req.volume as i8, addr);
                sink.success(Empty::default()).await.unwrap();
            } else {
                sink.fail(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    format!("Invalid Request Address: {}", from_utf8(bt_addr).unwrap()),
                ))
                .await
                .unwrap();
            }
        })
    }
}
