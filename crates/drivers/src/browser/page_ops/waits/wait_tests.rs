use crate::browser::BrowserDriver;

#[tokio::test(flavor = "current_thread")]
async fn wait_ms_does_not_require_a_live_browser_session() {
    let driver = BrowserDriver::new();
    let waited_ms = driver.wait_ms(1).await.expect("fixed wait should succeed");
    assert_eq!(waited_ms, 1);
}
