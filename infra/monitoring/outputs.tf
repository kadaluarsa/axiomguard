# Monitoring Module Outputs

output "latency_dashboard_id" {
  description = "ID of the latency monitoring dashboard"
  value       = google_monitoring_dashboard.axiomguard_latency_dashboard.id
}

output "latency_dashboard_name" {
  description = "Name of the latency monitoring dashboard"
  value       = google_monitoring_dashboard.axiomguard_latency_dashboard.display_name
}

output "gpu_dashboard_id" {
  description = "ID of the GPU metrics dashboard"
  value       = google_monitoring_dashboard.axiomguard_gpu_dashboard.id
}

output "gpu_dashboard_name" {
  description = "Name of the GPU metrics dashboard"
  value       = google_monitoring_dashboard.axiomguard_gpu_dashboard.display_name
}

output "high_latency_alert_id" {
  description = "ID of the high latency alert policy"
  value       = google_monitoring_alert_policy.high_latency_p95.id
}

output "high_error_rate_alert_id" {
  description = "ID of the high error rate alert policy"
  value       = google_monitoring_alert_policy.high_error_rate.id
}

output "instance_count_alert_id" {
  description = "ID of the instance count alert policy"
  value       = google_monitoring_alert_policy.instance_count_approaching_limit.id
}

output "gpu_memory_alert_id" {
  description = "ID of the GPU memory alert policy"
  value       = google_monitoring_alert_policy.gpu_memory_high.id
}

output "email_notification_channel_id" {
  description = "ID of the email notification channel (if created)"
  value       = length(google_monitoring_notification_channel.email_channel) > 0 ? google_monitoring_notification_channel.email_channel[0].id : null
}

output "dashboard_urls" {
  description = "URLs to access the dashboards in Cloud Console"
  value = {
    latency_dashboard = "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.axiomguard_latency_dashboard.id}?project=${var.gcp_project_id}"
    gpu_dashboard     = "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.axiomguard_gpu_dashboard.id}?project=${var.gcp_project_id}"
  }
}
