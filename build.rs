fn main() {
    #[cfg(any(
        feature = "secret-service-dbus-std",
        feature = "secret-service-dbus-tokio"
    ))]
    generate_dbus_apis();
}

#[cfg(any(
    feature = "secret-service-dbus-std",
    feature = "secret-service-dbus-tokio"
))]
fn generate_dbus_apis() {
    let _ = std::fs::remove_file("./src/secret_service/dbus/blocking/api.rs");
    let _ = std::fs::remove_file("./src/secret_service/dbus/nonblock/api.rs");

    let xml = include_str!("./src/secret_service/dbus/api.xml");

    let mut opts = dbus_codegen::GenOpts::default();
    opts.methodtype = None;

    #[cfg(feature = "secret-service-dbus-std")]
    generate_dbus_blocking_api(xml, &mut opts);

    #[cfg(feature = "secret-service-dbus-tokio")]
    generate_dbus_nonblock_api(xml, &mut opts);
}

#[cfg(feature = "secret-service-dbus-std")]
fn generate_dbus_blocking_api(xml: &str, opts: &mut dbus_codegen::GenOpts) {
    opts.connectiontype = dbus_codegen::ConnectionType::Blocking;

    let api = dbus_codegen::generate(xml, &opts).expect("should generate D-Bus blocking API");

    std::fs::write("./src/secret_service/dbus/blocking/api.rs", api)
        .expect("should write generated Secret Service blocking API");
}

#[cfg(feature = "secret-service-dbus-tokio")]
fn generate_dbus_nonblock_api(xml: &str, opts: &mut dbus_codegen::GenOpts) {
    opts.connectiontype = dbus_codegen::ConnectionType::Nonblock;

    let api = dbus_codegen::generate(xml, &opts).expect("should generate D-Bus nonblock API");

    std::fs::write("./src/secret_service/dbus/nonblock/api.rs", api)
        .expect("should write generated Secret Service nonblock API");
}
