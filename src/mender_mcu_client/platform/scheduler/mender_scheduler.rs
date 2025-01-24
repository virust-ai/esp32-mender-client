extern crate alloc;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::result::Result;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};
use esp_println::println;
use heapless::{String, Vec};

// Constants
const CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH: usize = 10;
const MAX_NAME_LENGTH: usize = 32;

// Type definitions
pub type MenderStatus = Result<(), &'static str>;

// Define type alias for the future
pub type MenderFuture = Pin<Box<dyn Future<Output = MenderStatus> + 'static>>;

/// Parameters for a work item
#[derive(Clone)]
pub struct MenderSchedulerWorkParams {
    pub function: fn() -> MenderFuture,
    pub period: u32, // seconds, negative or zero disables periodic execution
    pub name: String<MAX_NAME_LENGTH>,
}

/// Context for a work item including its state
#[derive(Clone)]
pub struct MenderSchedulerWorkContext {
    pub params: MenderSchedulerWorkParams,
    pub is_executing: bool,
    pub activated: bool,
    execution_count: u32,
    last_execution: Option<Instant>,
}

/// Command for the scheduler
#[derive(Clone)]
pub enum SchedulerCommand {
    AddWork(MenderSchedulerWorkContext),
    RemoveWork(String<MAX_NAME_LENGTH>),
    RemoveAllWorks,
    SetPeriod(String<MAX_NAME_LENGTH>, u32), // Just name and period
}

// Static instances for synchronization and communication
static WORK_QUEUE: Channel<
    CriticalSectionRawMutex,
    SchedulerCommand,
    CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH,
> = Channel::new();
//static WORK_STATUS_MUTEX: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// Main scheduler struct
pub struct Scheduler {
    work_queue: &'static Channel<
        CriticalSectionRawMutex,
        SchedulerCommand,
        CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH,
    >,
}

// WorkParams implementation
impl MenderSchedulerWorkParams {
    pub fn new(
        function: fn() -> MenderFuture,
        period: u32,
        name: &str,
    ) -> Result<Self, &'static str> {
        let mut fixed_name = String::new();
        fixed_name.push_str(name).map_err(|_| "Name too long")?;

        Ok(Self {
            function,
            period,
            name: fixed_name,
        })
    }
}

// WorkContext implementation
impl MenderSchedulerWorkContext {
    pub fn new(params: MenderSchedulerWorkParams) -> Self {
        Self {
            params,
            is_executing: false,
            activated: false,
            execution_count: 0,
            last_execution: None,
        }
    }

    /// Execute the work if conditions are met
    async fn execute(&mut self) -> MenderStatus {
        //let _lock = WORK_STATUS_MUTEX.lock().await;

        if self.is_executing || !self.activated {
            return Err("Work is already executing or not activated");
        }

        self.is_executing = true;
        self.execution_count += 1;

        println!(
            "Executing work '{}': Execution #{}",
            self.params.name, self.execution_count
        );

        // Execute the work function
        let result = (self.params.function)().await;
        self.is_executing = false;
        self.last_execution = Some(Instant::now());
        result
    }

    /// Check if work should be executed based on its period
    pub fn should_execute(&self) -> bool {
        if !self.activated || self.is_executing {
            return false;
        }

        if let Some(last_exec) = self.last_execution {
            let elapsed = Instant::now().duration_since(last_exec);
            elapsed.as_secs() >= self.params.period as u64
        } else {
            true // First execution
        }
    }

    /// Activate the work
    async fn activate(&mut self) -> MenderStatus {
        //println!("Attempting to acquire lock for '{}'", self.params.name);
        //let _lock = WORK_STATUS_MUTEX.lock().await;
        //println!("Lock acquired for '{}'", self.params.name);
        if !self.activated {
            self.activated = true;
            println!("Work '{}' activated", self.params.name);
        } else {
            println!("Work '{}' is already activated", self.params.name);
        }
        Ok(())
    }

    /// Deactivate the work
    async fn deactivate(&mut self) -> MenderStatus {
        //let _lock = WORK_STATUS_MUTEX.lock().await;
        if self.activated {
            while self.is_executing {
                Timer::after(Duration::from_millis(10)).await;
            }
            self.activated = false;
            println!("Work '{}' deactivated", self.params.name);
            Ok(())
        } else {
            Err("Work is not activated")
        }
    }

    /// Set the period for periodic execution
    #[allow(dead_code)]
    async fn set_period(&mut self, period: u32) -> MenderStatus {
        //let _lock = WORK_STATUS_MUTEX.lock().await;
        self.params.period = period;
        println!("Work '{}' period set to {}s", self.params.name, period);
        Ok(())
    }
}

// Scheduler implementation
impl Scheduler {
    pub const fn new() -> Self {
        Self {
            work_queue: &WORK_QUEUE,
        }
    }

    pub fn init(&'static self, spawner: Spawner) -> Result<(), &'static str> {
        println!("Initializing scheduler...");
        if spawner.spawn(work_queue_task()).is_err() {
            println!("Failed to spawn work queue task");
            return Err("Failed to spawn work queue task");
        }
        println!("Scheduler initialized successfully");
        Ok(())
    }

    pub async fn create_work(
        &self,
        params: MenderSchedulerWorkParams,
    ) -> Result<MenderSchedulerWorkContext, &'static str> {
        let work = MenderSchedulerWorkContext::new(params);
        println!("Created work '{}'", work.params.name);
        Ok(work)
    }

    pub async fn schedule_work(
        &self,
        work: MenderSchedulerWorkContext,
    ) -> Result<(), &'static str> {
        println!(
            "Scheduling work '{}' with period: {}s",
            work.params.name, work.params.period
        );
        self.work_queue.send(SchedulerCommand::AddWork(work)).await;
        Ok(())
    }

    pub async fn delete_work(&self, name: &str) -> Result<(), &'static str> {
        let mut fixed_name = String::new();
        fixed_name.push_str(name).map_err(|_| "Name too long")?;
        println!("Deleting work '{}'", name);
        self.work_queue
            .send(SchedulerCommand::RemoveWork(fixed_name))
            .await;
        Ok(())
    }

    pub async fn delete_all_works(&self) -> Result<(), &'static str> {
        println!("Removing all scheduled works");
        self.work_queue.send(SchedulerCommand::RemoveAllWorks).await;
        Ok(())
    }
}

/// Main work queue task that processes all works
#[embassy_executor::task]
async fn work_queue_task() {
    println!("Work queue task started");
    let mut works: Vec<MenderSchedulerWorkContext, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH> =
        Vec::new();

    loop {
        // Try to receive new commands
        while let Ok(command) = WORK_QUEUE.try_receive() {
            match command {
                SchedulerCommand::AddWork(work) => {
                    // Check if work with same name already exists
                    if works.iter().any(|w| w.params.name == work.params.name) {
                        println!("Work '{}' already in queue", work.params.name);
                    } else if works.push(work).is_err() {
                        println!("Work queue is full");
                    }
                }
                SchedulerCommand::RemoveWork(name) => {
                    if let Some(pos) = works.iter().position(|w| w.params.name == name) {
                        works.remove(pos);
                        println!("Work '{}' removed from scheduler", name);
                    }
                }
                SchedulerCommand::RemoveAllWorks => {
                    works.clear();
                    println!("All works removed from scheduler");
                }

                SchedulerCommand::SetPeriod(name, new_period) => {
                    if let Some(work) = works.iter_mut().find(|w| w.params.name == name) {
                        work.params.period = new_period;
                        println!("Work '{}' period updated to {}s", name, new_period);
                    }
                }
            }
        }

        // Process all works
        for work in works.iter_mut() {
            if work.should_execute() {
                if let Err(e) = work.execute().await {
                    println!("Work '{}' failed: {}", work.params.name, e);
                }
            }
        }

        // Small delay before next check
        Timer::after(Duration::from_millis(100)).await;
    }
}

// Static scheduler instance
static SCHEDULER: Scheduler = Scheduler::new();

// Public API functions

/// Initialize the scheduler
pub fn mender_scheduler_init(spawner: Spawner) -> Result<(), &'static str> {
    SCHEDULER.init(spawner)
}

/// Create a new work
pub async fn mender_scheduler_work_create(
    function: fn() -> MenderFuture,
    period: u32,
    name: &'static str,
) -> Result<MenderSchedulerWorkContext, &'static str> {
    log_info!("mender_scheduler_work_create", "name" => name);
    let params = MenderSchedulerWorkParams::new(function, period, name)?;
    SCHEDULER.create_work(params).await
}

/// Activate a work
pub async fn mender_scheduler_work_activate(
    work: &mut MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_activate", "name" => work.params.name);
    work.activate().await?;
    SCHEDULER.schedule_work(work.clone()).await
}

/// Deactivate a work
pub async fn mender_scheduler_work_deactivate(
    work: &mut MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_deactivate", "name" => work.params.name);
    work.deactivate().await
}

/// Set the period of a work
pub async fn mender_scheduler_work_set_period(
    work: &mut MenderSchedulerWorkContext,
    period: u32,
) -> Result<(), &'static str> {
    //work.set_period(period).await
    let mut fixed_name = String::new();
    fixed_name
        .push_str(&work.params.name)
        .map_err(|_| "Name too long")?;
    println!(
        "Setting period for work '{}' to {}s",
        work.params.name, period
    );
    WORK_QUEUE
        .send(SchedulerCommand::SetPeriod(fixed_name, period))
        .await;
    Ok(())
}

pub async fn mender_scheduler_work_execute(
    work: &MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_execute", "name" => work.params.name);
    SCHEDULER.schedule_work(work.clone()).await
}

// /// Schedule a work for execution
// pub async fn mender_schedule_work_start(work: MenderSchedulerWorkContext) -> Result<(), &'static str> {
//     SCHEDULER.schedule_work(work).await
// }

/// Delete a work
pub async fn mender_scheduler_work_delete(
    work: &MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_delete", "name" => work.params.name);
    SCHEDULER.delete_work(&work.params.name).await
}

/// Delete all works
#[allow(dead_code)]
pub async fn mender_scheduler_work_delete_all() -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_delete_all");
    SCHEDULER.delete_all_works().await
}
