fn main() {
    #[cfg(any(feature = "blocking", feature = "nonblock"))]
    generate_dbus_apis();
}

#[cfg(any(feature = "blocking", feature = "nonblock"))]
fn generate_dbus_apis() {
    let _ = std::fs::remove_file("./src/generated/blocking.rs");
    let _ = std::fs::remove_file("./src/generated/nonblock.rs");

    let mut opts = dbus_codegen::GenOpts::default();
    opts.methodtype = None;

    #[cfg(feature = "blocking")]
    generate_dbus_blocking_api(&mut opts);

    #[cfg(feature = "nonblock")]
    generate_dbus_nonblock_api(&mut opts);
}

#[cfg(feature = "blocking")]
fn generate_dbus_blocking_api(opts: &mut dbus_codegen::GenOpts) {
    const XML: &'static str = include_str!("./api.xml");

    opts.connectiontype = dbus_codegen::ConnectionType::Blocking;

    let api = dbus_codegen::generate(XML, &opts).expect("should generate D-Bus blocking API");

    std::fs::write("./src/generated/blocking.rs", api)
        .expect("should write generated Secret Service blocking API");
}

#[cfg(feature = "nonblock")]
fn generate_dbus_nonblock_api(opts: &mut dbus_codegen::GenOpts) {
    const XML: &'static str = include_str!("./api.xml");

    opts.connectiontype = dbus_codegen::ConnectionType::Nonblock;

    let api = dbus_codegen::generate(XML, &opts).expect("should generate D-Bus nonblock API");

    std::fs::write("./src/generated/nonblock.rs", api)
        .expect("should write generated Secret Service nonblock API");
}
