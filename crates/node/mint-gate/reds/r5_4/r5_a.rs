// Codex batch-3 r5 MINOR fixture: an expression fragment holding a draw, read at its include site.
{
    let mut b = [0u8; 1];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b[0]
}
