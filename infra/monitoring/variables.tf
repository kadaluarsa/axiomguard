# Monitoring Module Variables

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run service"
  type        = string
}

variable "cloud_run_service_name" {
  description = "Name of the Cloud Run service to monitor"
  type        = string
}

variable "notification_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = ""
}

variable "notification_channels" {
  description = "List of notification channel IDs to use for alerts"
  type        = list(string)
  default     = []
}

variable "latency_threshold_p95" {
  description = "p95 latency threshold in milliseconds for alerting"
  type        = number
  default     = 100
}

variable "error_rate_threshold" {
  description = "Error rate threshold percentage for alerting"
  type        = number
  default     = 1.0
}

variable "instance_count_threshold" {
  description = "Instance count threshold as percentage of max"
  type        = number
  default     = 80
}

variable "max_instance_count" {
  description = "Maximum instance count for the service"
  type        = number
  default     = 16
}
