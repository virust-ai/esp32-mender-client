#![no_std]
#![no_main]

extern crate alloc;
use alloc::format;
use alloc::string::ToString;
use embassy_executor::Spawner;
use embassy_net::Runner;
use embassy_net::StackResources;
use embassy_time::{Duration, Timer};
use esp32_mender_client::external::esp_hal_ota::OtaImgState;
use esp32_mender_client::mender_mcu_client::platform::flash::mender_flash::mender_flash_confirm_image;
use esp32_mender_client::mender_mcu_client::platform::flash::mender_flash::mender_flash_is_image_confirmed;
use esp_backtrace as _;
use esp_hal::efuse::Efuse;
use esp_hal::{clock::CpuClock, rng::Trng, timer::timg::TimerGroup};
use esp_println::println;
use esp_storage::FlashStorage;
use esp_wifi::{
    init,
    wifi::{
        ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiStaDevice,
        WifiState,
    },
    EspWifiController,
};

use esp32_mender_client::external::esp_hal_ota::Ota;
use esp32_mender_client::mender_mcu_client::add_ons::inventory::mender_inventory::{
    MenderInventoryConfig, MENDER_INVENTORY_ADDON_INSTANCE,
};
use esp32_mender_client::mender_mcu_client::core::mender_client::{
    mender_client_activate, mender_client_init, MenderClientCallbacks, MenderClientConfig,
};
use esp32_mender_client::mender_mcu_client::core::mender_utils::{
    DeploymentStatus, KeyStore, KeyStoreItem, MenderResult, MenderStatus,
};
use esp32_mender_client::mender_mcu_client::platform::fs::mender_littlefs::{
    mender_fs_init, mender_fs_read_file, mender_fs_write_file,
};
use esp32_mender_client::mender_mcu_client::{
    add_ons::inventory::mender_inventory, core::mender_client,
    platform::scheduler::mender_scheduler::work_queue_task,
};

#[allow(unused_imports)]
use esp32_mender_client::{log_debug, log_error, log_info, log_warn};

const WIFI_SSID: &str = env!("MENDER_CLIENT_WIFI_SSID");
const WIFI_PSK: &str = env!("MENDER_CLIENT_WIFI_PSK");

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

// Example usage:
fn network_connect_cb() -> MenderResult<()> {
    log_info!("network_connect_cb");
    // Implementation
    Ok((MenderStatus::Ok, ()))
}

fn network_release_cb() -> MenderResult<()> {
    log_info!("network_release_cb");
    // Implementation
    Ok((MenderStatus::Ok, ()))
}

fn authentication_success_cb() -> MenderResult<()> {
    log_info!("authentication_success_cb");

    /* Validate the image if it is still pending */
    /* Note it is possible to do multiple diagnosic tests before validating the image */
    /* In this example, authentication success with the mender-server is enough */
    if let Err(e) = mender_flash_confirm_image() {
        log_error!("Failed to confirm image, error: {:?}", e);
        return Err(MenderStatus::Failed);
    }
    Ok((MenderStatus::Ok, ()))
}

fn authentication_failure_cb() -> MenderResult<()> {
    log_info!("authentication_failure_cb");

    if !mender_flash_is_image_confirmed() {
        log_error!("Image is not confirmed");
        return Err(MenderStatus::Failed);
    }
    Ok((MenderStatus::Ok, ()))
}

fn deployment_status_cb(status: DeploymentStatus, message: Option<&str>) -> MenderResult<()> {
    log_info!(
        "deployment_status_cb, status: {}, message: {}",
        status,
        message.unwrap_or("")
    );

    Ok((MenderStatus::Ok, ()))
}

fn restart_cb() -> MenderResult<()> {
    log_info!("restart_cb");

    esp_hal::reset::software_reset();

    Ok((MenderStatus::Ok, ()))
}

// Make the config static
static INVENTORY_CONFIG: MenderInventoryConfig = MenderInventoryConfig {
    refresh_interval: 0,
};

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        config.cpu_clock = CpuClock::max();
        config
    });
    esp_alloc::heap_allocator!(120 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let timg1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timg1.timer0);
    let trng = &mut *mk_static!(Trng<'static>, Trng::new(peripherals.RNG, peripherals.ADC1));

    // Initialize the Mender filesystem
    match mender_fs_init().await {
        Ok(_) => {
            log_info!("Mender filesystem initialized successfully");

            // Example: Write a file
            let test_data = b"Hello, ESP32-C6 with Mender LittleFS!";
            match mender_fs_write_file("test.txt", test_data).await {
                Ok(_) => {
                    log_info!("File written successfully");

                    // Example: Read the file back
                    match mender_fs_read_file("test.txt").await {
                        Ok((_, data_vec)) => {
                            if let Ok(content) = core::str::from_utf8(&data_vec) {
                                log_info!("Read from file: {}", content);
                            }
                        }
                        Err(e) => log_error!("Failed to read file: {:?}", e),
                    }
                }
                Err(e) => log_error!("Failed to write file: {:?}", e),
            }
        }
        Err(e) => {
            log_error!("Failed to initialize Mender filesystem: {:?}", e);
        }
    }

    let init = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, trng.rng, peripherals.RADIO_CLK).unwrap()
    );

    let wifi = peripherals.WIFI;
    let (wifi_interface, controller) =
        esp_wifi::wifi::new_with_mode(init, wifi, WifiStaDevice).unwrap();
    let config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (trng.rng.random() as u64) << 32 | trng.rng.random() as u64;
    println!(
        "Test {}-{}",
        env!("ESP_DEVICE_NAME"),
        env!("ESP_DEVICE_VERSION")
    );
    // // Init network stack
    // let stack = &*mk_static!(
    //     Stack<WifiDevice<'_, WifiStaDevice>>,
    //     Stack::new(
    //         wifi_interface,
    //         config,
    //         mk_static!(StackResources<3>, StackResources::<3>::new()),
    //         seed
    //     )
    // );
    // Init network stack
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    let mut ota = match Ota::new(FlashStorage::new()) {
        Ok(ota) => ota,
        Err(e) => {
            log_error!("Failed to create OTA instance, error: {:?}", e);
            panic!("Failed to create OTA instance");
        }
    };

    // Log current partition info
    if let Some(part) = ota.get_currently_booted_partition() {
        log_info!(
            "Running from partition: {}, base: {}",
            format_args!("ota_{}", part),
            format_args!("0x{:x}", if part == 0 { 0x10000 } else { 0x1c0000 })
        );
    }

    // Verify partition state
    if let Ok(state) = ota.get_ota_image_state() {
        if state != OtaImgState::EspOtaImgValid {
            log_warn!("Current partition not marked as valid");
            // Optionally mark as valid if needed
            //let _ = ota.ota_mark_app_valid();
        }
    }

    spawner
        .spawn(connection(controller))
        .expect("connection spawn");
    spawner.spawn(net_task(runner)).expect("net task spawn");
    spawner
        .spawn(work_queue_task())
        .expect("work queue task spawn");
    spawner.spawn(test_task()).expect("test task spawn");

    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    log_info!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config_v4() {
            log_info!("Got IP: {}", config.address);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    log_info!("Starting async main...");

    let mac_address = Efuse::mac_address();
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_address[0],
        mac_address[1],
        mac_address[2],
        mac_address[3],
        mac_address[4],
        mac_address[5]
    );

    let identity = {
        let mut store = KeyStore::new();
        store.set_item("mac", &mac_str).unwrap();
        store
    };

    let device_type = env!("ESP_DEVICE_TYPE");
    let device_name = env!("ESP_DEVICE_NAME");
    let device_version = env!("ESP_DEVICE_VERSION");
    let tenant_token = option_env!("MENDER_CLIENT_TENANT_TOKEN");
    let config = MenderClientConfig::new(
        identity,
        &format!("{}-{}", device_name, device_version),
        device_type,
        option_env!("MENDER_CLIENT_URL").unwrap_or("https://hosted.mender.io"),
        tenant_token,
    )
    .with_auth_interval(60)
    .with_update_interval(120)
    .with_recommissioning(false)
    .with_device_update_done_reset(true);

    // Creating an instance:
    let callbacks = MenderClientCallbacks::new(
        network_connect_cb,
        network_release_cb,
        authentication_success_cb,
        authentication_failure_cb,
        deployment_status_cb,
        restart_cb,
    );

    mender_client_init(&config, &callbacks, trng, stack)
        .await
        .expect("Failed to init mender client");

    // In your main function or setup code:
    match mender_client::mender_client_register_addon(
        &MENDER_INVENTORY_ADDON_INSTANCE,
        Some(&INVENTORY_CONFIG), // Use the static config
        None,
    )
    .await
    {
        Ok(_) => {
            log_info!("Mender inventory add-on registered successfully");
        }
        Err(_) => {
            log_error!("Unable to register mender-inventory add-on");
            panic!("Failed to register mender-inventory add-on");
        }
    }

    // Define the inventory items
    let inventory = [
        KeyStoreItem {
            name: "mender-mcu-client".to_string(),
            value: env!("CARGO_PKG_VERSION").to_string(),
        },
        KeyStoreItem {
            name: "latitude".to_string(),
            value: "45.8325".to_string(),
        },
        KeyStoreItem {
            name: "longitude".to_string(),
            value: "6.864722".to_string(),
        },
    ];

    let mut keystore = KeyStore::new();
    for item in &inventory {
        keystore.set_item(&item.name, &item.value).unwrap();
    }
    // Set the inventory
    match mender_inventory::mender_inventory_set(&keystore).await {
        Ok(_) => {
            log_info!("Mender inventory set successfully");
        }
        Err(_) => {
            log_error!("Unable to set mender inventory");
        }
    }

    match mender_client_activate().await {
        MenderStatus::Done => {
            log_info!("Client activated successfully");
        }
        _ => panic!("Failed to activate client"),
    };

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy_executor::task]
async fn connection(
    mut controller: WifiController<'static>,
    //stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>,
) {
    log_info!("start connection task");
    log_info!("turn off power saving mode");
    controller
        .set_power_saving(esp_wifi::config::PowerSaveMode::None)
        .unwrap();
    loop {
        if esp_wifi::wifi::wifi_state() == WifiState::StaConnected {
            // wait until we're no longer connected
            controller.wait_for_event(WifiEvent::StaDisconnected).await;
            Timer::after(Duration::from_millis(5000)).await
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: WIFI_SSID.try_into().expect("Wifi ssid parse"),
                password: WIFI_PSK.try_into().expect("Wifi psk parse"),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            log_info!("Starting wifi");
            controller.start_async().await.unwrap();
            log_info!("Wifi started!");
        }
        log_info!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => {
                log_info!("Wifi connected!");

                // loop {
                //     if stack.is_link_up() {
                //         break;
                //     }
                //     Timer::after(Duration::from_millis(500)).await;
                // }
            }
            Err(e) => {
                log_error!("Failed to connect to wifi: {:?}", e);
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static, WifiStaDevice>>) {
    runner.run().await
}

#[embassy_executor::task]
async fn test_task() {
    loop {
        log_info!("test_task");
        Timer::after(Duration::from_secs(2)).await;
    }
}
