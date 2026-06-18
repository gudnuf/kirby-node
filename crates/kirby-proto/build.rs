fn main() {
    // Compile the gateway proto into both client and server stubs. The daemon
    // uses the server side, the genome uses the client side.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/node_gateway.proto"], &["proto"])
        .expect("compile node_gateway.proto");

    println!("cargo:rerun-if-changed=proto/node_gateway.proto");
}
