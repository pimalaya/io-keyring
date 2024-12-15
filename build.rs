fn main() {
    #[cfg(feature = "ss-dbus-std")]
    generate_dbus_apis();
}

#[cfg(feature = "ss-dbus-std")]
fn generate_dbus_apis() {
    let _ = std::fs::remove_file("./src/secret_service/dbus_blocking/api.rs");

    let xml = include_str!("./src/secret_service/api.xml");

    let mut opts = dbus_codegen::GenOpts::default();
    opts.methodtype = None;

    #[cfg(feature = "ss-dbus-std")]
    generate_dbus_blocking_api(xml, &mut opts);
}

#[cfg(feature = "ss-dbus-std")]
fn generate_dbus_blocking_api(xml: &str, opts: &mut dbus_codegen::GenOpts) {
    opts.connectiontype = dbus_codegen::ConnectionType::Blocking;

    let api = dbus_codegen::generate(xml, &opts).expect("should generate D-Bus blocking API");

    std::fs::write("./src/secret_service/dbus_blocking/api.rs", api)
        .expect("should write generated Secret Service blocking API");
}
