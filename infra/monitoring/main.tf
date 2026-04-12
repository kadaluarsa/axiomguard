# Terraform configuration for AxiomGuard Monitoring
# This module creates dashboards and alerts for the Cloud Run GPU service

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

# Data source to get the Cloud Run service information
data "google_cloud_run_v2_service" "llm_service" {
  name     = var.cloud_run_service_name
  location = var.gcp_region
}
