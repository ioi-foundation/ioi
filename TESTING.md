cargo build --release --features="depin-sdk-chain/mvsc-bin"

./target/release/mvsc --state-file node1.json --config-dir ./config
./target/release/mvsc --state-file node2.json --config-dir ./config