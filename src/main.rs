extern crate env_logger;
extern crate clap;

#[macro_use] extern crate log;

use env_logger::{
  Builder,
  Env
};

use clap::{Command, Arg};
// use std::net::SocketAddr;
use pcap::{Device, Capture};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};

mod handlers;

fn get_requested_device<'a> (requested_device_s : &str, requested_device : &'a mut Device, vec_devices : &'a Vec<Device>) {
    for device in vec_devices {
        if &*device.name == requested_device_s {
                requested_device.name = device.name.clone();
                requested_device.desc = device.desc.clone();
                println!("-{} device has been captured!", requested_device_s);
        };
    };
}

fn main() {
  let flags = Command::new("traffic-by-ip-exporter")
    .version("0.1.0")
    .about("Prometheus exporter for traffic accounting by IP")
    .author("Luis Felipe Domínguez Vega <ldominguezvega@gmail.com>")
    .arg(Arg::new("interface")
      .short('i')
      .long("interface")
      .help("Interface for listen")
      .required(true)
    )
    .arg(Arg::new("port")
      .short('p')
      .long("port")
      .help("Host port to expose http server")
      .required(false)
      .default_value("9185")
    )
    .arg(Arg::new("host")
      .short('h')
      .long("host")
      .help("Address where to expose http server")
      .required(false)
      .default_value("0.0.0.0")
    )
    .get_matches();

  let (iface, expose_port, expose_host) = (
            flags.get_one::<String>("interface").unwrap(),
            flags.get_one::<String>("port").unwrap(),
            flags.get_one::<String>("host").unwrap(),
        );

  Builder::from_env(Env::default().default_filter_or("info")).init();

  info!("Using interface: {}", iface);

  // Parse address used to bind exporter to.
  let addr_raw = expose_host.to_owned() + ":" + expose_port;
  let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

  // Start exporter.
  let (request_receiver, finished_sender) = PrometheusExporter::run_and_notify(addr);

  let label_vector = [
      "direction", 
      "src_ip",
      "dst_ip",
      "src_port",
      "dst_port"
  ];

  let traffic_by_ip_bits_opts = Opts::new("traffic_by_ip_bits", "Traffic by IP");
  traffic_by_ip_bits_opts.variable_labels(label_vector);

  let traffic_by_ip_bits = Gauge::with_opts(traffic_by_ip_bits_opts)
    .expect("Can't create gauge traffic_by_ip__bits");

  let r = Registry::new();
  r.register(Box::new(traffic_by_ip_bits.clone())).unwrap();

  let devices = Device::list();
  let mut main_device = Device::lookup().unwrap().unwrap();

  match devices {
    Ok(vec_devices) => {
      get_requested_device(&iface, &mut main_device, &vec_devices);
    }
    Err(_) => {
      error!("No devices found...");
      std::process::exit(1);
    }
  }
 
  if main_device.name != iface.to_owned() {
    std::process::exit(1);
  }

  let mut cap = Capture::from_device(main_device).unwrap()
    .promisc(false)
    .snaplen(5000)
    .open().unwrap();

  while let Ok(packet) = cap.next_packet() {
    let ethernet = EthernetPacket::new(packet.data).unwrap();
    match ethernet.get_ethertype() {
      EtherTypes::Ipv4 => {
        handlers::handle_ipv4_packet(iface, &ethernet);
      }
      _ => println!("unhandled packet: {:?}", ethernet),
    }
  }
}
