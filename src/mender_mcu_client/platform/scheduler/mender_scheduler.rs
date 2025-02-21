extern crate alloc;
#[allow(unused_imports)]
use crate::{log_debug, log_error, log_info, log_warn};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};
use heapless::{String, Vec};

// Constants
const CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH: usize = 10;
const MAX_NAME_LENGTH: usize = 32;

// Type definitions
type SchedulerStatus = Result<(), &'static str>;

// Define type alias for the future
pub(crate) type MenderFuture = Pin<Box<dyn Future<Output = SchedulerStatus> + 'static>>;

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
}

// Static instances for synchronization and communication
static WORK_QUEUE: Channel<
    CriticalSectionRawMutex,
    SchedulerCommand,
    CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH,
> = Channel::new();

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
    fn new(params: MenderSchedulerWorkParams) -> Self {
        Self {
            params,
            is_executing: false,
            activated: false,
            execution_count: 0,
            last_execution: None,
        }
    }

    /// Execute the work if conditions are met
    async fn execute(&mut self) -> SchedulerStatus {
        if self.is_executing || !self.activated {
            log_error!("Work is already executing or not activated");
            return Err("Work is already executing or not activated");
        }

        self.is_executing = true;
        self.execution_count += 1;

        log_info!(
            "Executing work '{}', period: {}, execution #{}",
            self.params.name,
            self.params.period,
            self.execution_count
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
    fn activate(&mut self) -> SchedulerStatus {
        if !self.activated {
            self.activated = true;
            log_info!("Work '{}' activated", self.params.name);
        } else {
            log_info!("Work '{}' is already activated", self.params.name);
        }
        Ok(())
    }

    /// Deactivate the work
    async fn deactivate(&mut self) -> SchedulerStatus {
        if self.activated {
            if self.is_executing {
                loop {
                    Timer::after(Duration::from_millis(10)).await;
                    if !self.is_executing {
                        break;
                    }
                }
            }
            self.activated = false;
            log_info!("Work '{}' deactivated", self.params.name);
            Ok(())
        } else {
            Err("Work is not activated")
        }
    }

    /// Set the period for periodic execution
    #[allow(dead_code)]
    fn set_period(&mut self, period: u32) -> SchedulerStatus {
        self.params.period = period;
        log_info!("Work '{}' period set to {}s", self.params.name, period);
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

    fn create_work(
        &self,
        params: MenderSchedulerWorkParams,
    ) -> Result<MenderSchedulerWorkContext, &'static str> {
        let work = MenderSchedulerWorkContext::new(params);
        log_info!("Created work '{}'", work.params.name);
        Ok(work)
    }

    async fn schedule_work(&self, work: MenderSchedulerWorkContext) -> Result<(), &'static str> {
        log_info!(
            "Scheduling work '{}' with period: {}s",
            work.params.name,
            work.params.period
        );
        self.work_queue.send(SchedulerCommand::AddWork(work)).await;
        Ok(())
    }

    async fn delete_work(&self, name: &str) -> Result<(), &'static str> {
        let mut fixed_name = String::new();
        fixed_name.push_str(name).map_err(|_| "Name too long")?;
        log_info!("Deleting work '{}'", name);
        self.work_queue
            .send(SchedulerCommand::RemoveWork(fixed_name))
            .await;
        Ok(())
    }

    async fn delete_all_works(&self) -> Result<(), &'static str> {
        log_info!("Removing all scheduled works");
        self.work_queue.send(SchedulerCommand::RemoveAllWorks).await;
        Ok(())
    }
}

/// Main work queue task that processes all works
#[embassy_executor::task]
pub async fn work_queue_task() {
    log_info!("Work queue task started");
    let mut works: Vec<MenderSchedulerWorkContext, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH> =
        Vec::new();

    loop {
        // Try to receive new commands
        while let Ok(command) = WORK_QUEUE.try_receive() {
            match command {
                SchedulerCommand::AddWork(work) => {
                    log_info!("Adding work '{}' to scheduler", work.params.name);
                    // Check if work with same name already exists
                    if works.iter().any(|w| w.params.name == work.params.name) {
                        log_info!("Work '{}' already in queue", work.params.name);
                    } else if works.push(work).is_err() {
                        log_warn!("Work queue is full");
                    }
                }
                SchedulerCommand::RemoveWork(name) => {
                    if let Some(pos) = works.iter().position(|w| w.params.name == name) {
                        works.remove(pos);
                        log_info!("Work '{}' removed from scheduler", name);
                    }
                }
                SchedulerCommand::RemoveAllWorks => {
                    works.clear();
                    log_info!("All works removed from scheduler");
                }
            }
        }

        // Process all works
        for work in works.iter_mut() {
            if work.should_execute() {
                if let Err(e) = work.execute().await {
                    log_error!("Work '{}' failed: {}", work.params.name, e);
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

/// Create a new work
pub(crate) fn mender_scheduler_work_create(
    function: fn() -> MenderFuture,
    period: u32,
    name: &'static str,
) -> Result<MenderSchedulerWorkContext, &'static str> {
    log_info!("mender_scheduler_work_create for {}", name);
    let params = MenderSchedulerWorkParams::new(function, period, name)?;
    SCHEDULER.create_work(params)
}

/// Activate a work
pub(crate) async fn mender_scheduler_work_activate(
    work: &mut MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_activate for {}", work.params.name);
    work.activate()?;
    SCHEDULER.schedule_work(work.clone()).await
}

/// Deactivate a work
pub(crate) async fn mender_scheduler_work_deactivate(
    work: &mut MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_deactivate for {}", work.params.name);
    work.deactivate().await
}

/// Set the period of a work
pub(crate) fn mender_scheduler_work_set_period(
    work: &mut MenderSchedulerWorkContext,
    period: u32,
) -> Result<(), &'static str> {
    log_info!(
        "Changing period for work '{}' to {}s",
        work.params.name,
        period
    );
    work.params.period = period;

    Ok(())
}

pub(crate) async fn mender_scheduler_work_execute(
    work: &MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_execute for {}", work.params.name);
    SCHEDULER.schedule_work(work.clone()).await
}

// /// Schedule a work for execution
// pub async fn mender_schedule_work_start(work: MenderSchedulerWorkContext) -> Result<(), &'static str> {
//     SCHEDULER.schedule_work(work).await
// }

/// Delete a work
pub(crate) async fn mender_scheduler_work_delete(
    work: &MenderSchedulerWorkContext,
) -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_delete for {}", work.params.name);
    SCHEDULER.delete_work(&work.params.name).await
}

/// Delete all works
pub(crate) async fn mender_scheduler_work_delete_all() -> Result<(), &'static str> {
    log_info!("mender_scheduler_work_delete_all");
    SCHEDULER.delete_all_works().await
}

// Add Default implementation
impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
