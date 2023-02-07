use std::future::Future;

use tokio::task::LocalSet;

pub fn start_test(f: impl Future<Output = ()>) {
    tokio_test::block_on(async move {
        bt_common::init_logging();
        LocalSet::new().run_until(f).await;
    });
}
