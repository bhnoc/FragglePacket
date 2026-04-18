//! UI Components for FragglePacket Desktop

pub mod dashboard;
pub mod test_panel;
pub mod https_panel;
pub mod fuzzing_panel;
pub mod path_panel;
pub mod simulator;
pub mod results_display;

pub use dashboard::Dashboard;
pub use test_panel::TestPanel;
pub use https_panel::HttpsPanel;
pub use fuzzing_panel::FuzzingPanel;
pub use path_panel::PathPanel;
pub use simulator::Simulator;
pub use results_display::ResultsDisplay;
