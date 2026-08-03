//! UI Components for FragglePacket Desktop

pub mod dashboard;
pub mod fuzzing_panel;
pub mod history_panel;
pub mod https_panel;
pub mod logs_panel;
pub mod path_panel;
pub mod probes_panel;
pub mod report_panel;
pub mod results_display;
pub mod simulator;
pub mod target_input;
pub mod test_panel;

pub use dashboard::Dashboard;
pub use fuzzing_panel::FuzzingPanel;
pub use history_panel::HistoryPanel;
pub use https_panel::HttpsPanel;
pub use logs_panel::LogsPanel;
pub use path_panel::PathPanel;
pub use probes_panel::ProbesPanel;
pub use report_panel::ReportPanel;
pub use simulator::Simulator;
pub use test_panel::TestPanel;
