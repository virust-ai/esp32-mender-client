use crate::mender_mcu_client::core::mender_utils::MenderResult;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

pub struct MenderAddonInstance<C: 'static, CB: 'static> {
    /// Invoked to initialize the add-on
    pub init: fn(
        config: Option<&'static C>,
        callbacks: Option<&'static CB>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>,

    /// Invoked to activate the add-on
    pub activate: fn() -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>,

    /// Invoked to deactivate the add-on
    pub deactivate: fn() -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>,

    /// Invoked to cleanup the add-on
    pub exit: fn() -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>,
}

pub trait MenderAddon: Send + Sync {
    fn init(
        &self,
        config: Option<&'static ()>,
        callbacks: Option<&'static ()>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>;
    fn activate(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>;
    fn deactivate(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>;
    fn exit(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>>;
}

impl<C: 'static, CB: 'static> MenderAddon for MenderAddonInstance<C, CB> {
    fn init(
        &self,
        config: Option<&'static ()>,
        callbacks: Option<&'static ()>,
    ) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>> {
        // Cast the generic config and callbacks to the specific types
        let config = config.map(|c| unsafe { &*(c as *const () as *const C) });
        let callbacks = callbacks.map(|cb| unsafe { &*(cb as *const () as *const CB) });

        // Call the instance's init function
        (self.init)(config, callbacks)
    }

    fn activate(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>> {
        // Call the instance's activate function
        (self.activate)()
    }

    fn deactivate(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>> {
        // Call the instance's deactivate function
        (self.deactivate)()
    }

    fn exit(&self) -> Pin<Box<dyn Future<Output = MenderResult<()>> + Send + 'static>> {
        // Call the instance's exit function
        (self.exit)()
    }
}
