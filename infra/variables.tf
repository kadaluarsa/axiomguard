# Cloud Run GPU Service Variables

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = "anichinplus"
}

variable "gcp_region" {
  description = "GCP region for Cloud Run service"
  type        = string
  default     = "us-central1"
}

variable "cloud_run_gpu_service_name" {
  description = "Name of the Cloud Run GPU service"
  type        = string
  default     = "llm-inference-service"
}

variable "llm_container_image" {
  description = "Container image URL for LLM inference service"
  type        = string
}

variable "vllm_model_name" {
  description = "Model name or path for vLLM to load"
  type        = string
}

variable "vllm_max_context_length" {
  description = "Maximum context window length for the model"
  type        = number
  default     = 8192
}

variable "cloud_run_service_account_email" {
  description = "Service account email for Cloud Run service"
  type        = string
}

# Monitoring Configuration

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
