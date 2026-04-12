# Main Terraform configuration for AxiomGuard Cloud Run GPU service
# Deploys a Cloud Run service with NVIDIA L4 GPU for vLLM inference

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.0"
    }
  }

  # Local backend - state stored in .terraform/terraform.tfstate
  # For production, use GCS backend:
  # backend "gcs" {
  #   bucket = "your-terraform-state-bucket"
  #   prefix = "axiomguard/cloudrun-gpu"
  # }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Enable required Google Cloud APIs
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute_api" {
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "container_registry" {
  service            = "containerregistry.googleapis.com"
  disable_on_destroy = false
}

# Cloud Run v2 Service with NVIDIA L4 GPU for vLLM inference
resource "google_cloud_run_v2_service" "llm_gpu_service" {
  name     = var.cloud_run_gpu_service_name
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      # ✅ SCALE TO ZERO OPTIMIZATION
      # Setting min_instance_count = 0 - $2,800/month savings for pre-revenue startup
      # Accepts ~10 second cold start on first request after scale-to-zero
      min_instance_count = 0

      # Maximum instances for horizontal scaling under load
      # Reduced from 16 to 8 to prevent runaway costs during traffic spikes
      max_instance_count = 8
    }

    # vLLM optimized container configuration
    containers {
      image = var.llm_container_image

      resources {
        limits = {
          # L4 GPU requires minimum 8 vCPU and 32Gi memory
          cpu    = "8"
          memory = "32Gi"

          # NVIDIA L4 GPU configuration
          "nvidia.com/gpu" = "1"
        }
      }

      # vLLM performance optimization environment variables
      env {
        name  = "NVIDIA_VISIBLE_DEVICES"
        value = "all"
      }

      env {
        name  = "VLLM_LOG_LEVEL"
        value = "INFO"
      }

      env {
        name  = "VLLM_MODEL"
        value = var.vllm_model_name
      }

      env {
        name  = "VLLM_TENSOR_PARALLEL_SIZE"
        value = "1"
      }

      env {
        name  = "VLLM_GPU_MEMORY_UTILIZATION"
        value = "0.95"
      }

      env {
        name  = "VLLM_MAX_MODEL_LEN"
        value = tostring(var.vllm_max_context_length)
      }

      env {
        name  = "VLLM_ENABLE_PREFIX_CACHING"
        value = "True"
      }

      env {
        name  = "VLLM_DISABLE_LOG_STATS"
        value = "False"
      }

      # Cloud Run port configuration
      ports {
        container_port = 8000
      }

      # Health check configuration
      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 30
        period_seconds        = 10
        timeout_seconds       = 5
        failure_threshold     = 12
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds  = 30
        timeout_seconds = 5
      }
    }

    # Required for GPU access on Cloud Run
    service_account = var.cloud_run_service_account_email
  }

  # Traffic routing - 100% to latest ready revision
  traffic {
    percent = 100
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
  }

  depends_on = [
    google_project_service.run_api,
    google_project_service.compute_api
  ]
}

# Public invoker IAM binding - allows unauthenticated access to the service
resource "google_cloud_run_v2_service_iam_binding" "public_invoker" {
  name     = google_cloud_run_v2_service.llm_gpu_service.name
  location = google_cloud_run_v2_service.llm_gpu_service.location
  role     = "roles/run.invoker"

  members = [
    "allUsers"
  ]
}

# Monitoring Module
module "monitoring" {
  source = "./monitoring"

  gcp_project_id       = var.gcp_project_id
  gcp_region           = var.gcp_region
  cloud_run_service_name = var.cloud_run_gpu_service_name
  
  notification_email   = var.notification_email
  notification_channels = var.notification_channels
  
  latency_threshold_p95      = var.latency_threshold_p95
  error_rate_threshold       = var.error_rate_threshold
  instance_count_threshold   = var.instance_count_threshold
  max_instance_count         = var.max_instance_count
}

# Output the service details
output "cloud_run_service_url" {
  description = "URL of the deployed Cloud Run GPU service"
  value       = google_cloud_run_v2_service.llm_gpu_service.uri
}

output "cloud_run_service_name" {
  description = "Name of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.llm_gpu_service.name
}

output "cloud_run_service_location" {
  description = "Location of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.llm_gpu_service.location
}

output "cloud_run_service_status" {
  description = "Status of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.llm_gpu_service.conditions
}
