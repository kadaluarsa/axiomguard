# Alert Policies for AxiomGuard Cloud Run GPU Service

# Notification Channel - Email (optional, created only if email is provided)
resource "google_monitoring_notification_channel" "email_channel" {
  count        = var.notification_email != "" ? 1 : 0
  display_name = "AxiomGuard Alerts - Email"
  type         = "email"
  
  labels = {
    email_address = var.notification_email
  }
}

# Alert Policy: p95 Latency > threshold
resource "google_monitoring_alert_policy" "high_latency_p95" {
  display_name = "AxiomGuard: High p95 Latency (> ${var.latency_threshold_p95}ms)"
  combiner     = "OR"
  
  conditions {
    display_name = "p95 Request Latency > ${var.latency_threshold_p95}ms"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${var.cloud_run_service_name}"
        metric.type="run.googleapis.com/request_latencies"
      EOT
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_PERCENTILE_95"
      }
      
      comparison      = "COMPARISON_GT"
      threshold_value = var.latency_threshold_p95
      duration        = "0s"
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = length(var.notification_channels) > 0 ? var.notification_channels : (
    var.notification_email != "" ? [google_monitoring_notification_channel.email_channel[0].id] : []
  )
  
  alert_strategy {
    auto_close = "86400s"
  }
  
  severity = "WARNING"
  
  documentation {
    content = <<-EOT
      # High p95 Latency Alert
      
      The p95 latency for AxiomGuard LLM service has exceeded ${var.latency_threshold_p95}ms.
      
      ## Possible Causes
      - High request volume
      - GPU memory pressure
      - Model loading delays
      - Cold start overhead
      
      ## Recommended Actions
      1. Check instance count - consider increasing max instances
      2. Review GPU utilization metrics
      3. Check for any deployment issues
      4. Consider model optimization (quantization, etc.)
    EOT
    mime_type = "text/markdown"
  }
  
  labels = {
    service     = "axiomguard-llm"
    environment = "production"
    alert_type  = "latency"
  }
}

# Alert Policy: Error Rate > threshold
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "AxiomGuard: High Error Rate (> ${var.error_rate_threshold}%)"
  combiner     = "OR"
  
  conditions {
    display_name = "Error Rate > ${var.error_rate_threshold}%"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${var.cloud_run_service_name}"
        metric.type="run.googleapis.com/request_count"
        metric.labels.response_code_class="5xx"
      EOT
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_SUM"
      }
      
      denominator_filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${var.cloud_run_service_name}"
        metric.type="run.googleapis.com/request_count"
      EOT
      
      denominator_aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
      
      comparison      = "COMPARISON_GT"
      threshold_value = var.error_rate_threshold / 100
      duration        = "0s"
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = length(var.notification_channels) > 0 ? var.notification_channels : (
    var.notification_email != "" ? [google_monitoring_notification_channel.email_channel[0].id] : []
  )
  
  alert_strategy {
    auto_close = "86400s"
  }
  
  severity = "CRITICAL"
  
  documentation {
    content = <<-EOT
      # High Error Rate Alert
      
      The error rate for AxiomGuard LLM service has exceeded ${var.error_rate_threshold}%.
      
      ## Possible Causes
      - Service crashes or panics
      - GPU OOM (Out of Memory) errors
      - Model loading failures
      - Request timeout exceeded
      - Infrastructure issues
      
      ## Recommended Actions
      1. Check Cloud Run logs for specific error messages
      2. Review GPU memory utilization
      3. Check if model is loading correctly
      4. Verify service configuration
      5. Consider rolling back to previous version if needed
    EOT
    mime_type = "text/markdown"
  }
  
  labels = {
    service     = "axiomguard-llm"
    environment = "production"
    alert_type  = "error_rate"
  }
}

# Alert Policy: Instance Count Approaching Limits
resource "google_monitoring_alert_policy" "instance_count_approaching_limit" {
  display_name = "AxiomGuard: Instance Count Approaching Limit (${var.instance_count_threshold}%)"
  combiner     = "OR"
  
  conditions {
    display_name = "Instance Count > ${var.instance_count_threshold}% of max"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${var.cloud_run_service_name}"
        metric.type="run.googleapis.com/container/instance_count"
      EOT
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_SUM"
      }
      
      comparison      = "COMPARISON_GT"
      threshold_value = (var.max_instance_count * var.instance_count_threshold) / 100
      duration        = "300s"
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = length(var.notification_channels) > 0 ? var.notification_channels : (
    var.notification_email != "" ? [google_monitoring_notification_channel.email_channel[0].id] : []
  )
  
  alert_strategy {
    auto_close = "86400s"
  }
  
  severity = "WARNING"
  
  documentation {
    content = <<-EOT
      # Instance Count Approaching Limit Alert
      
      The instance count for AxiomGuard LLM service is approaching the configured maximum (${var.max_instance_count} instances, currently at ${var.instance_count_threshold}% threshold).
      
      ## Possible Causes
      - Sudden traffic spike
      - Increased request latency causing longer processing times
      - Cold starts consuming more instances
      - Insufficient max instance count configuration
      
      ## Recommended Actions
      1. Review current traffic patterns
      2. Consider increasing max_instance_count if sustained growth
      3. Check if request processing time has increased
      4. Review auto-scaling behavior in Cloud Run metrics
      5. Consider implementing request queuing/backpressure
    EOT
    mime_type = "text/markdown"
  }
  
  labels = {
    service     = "axiomguard-llm"
    environment = "production"
    alert_type  = "instance_count"
  }
}

# Alert Policy: GPU Memory Utilization
resource "google_monitoring_alert_policy" "gpu_memory_high" {
  display_name = "AxiomGuard: GPU Memory Utilization High (> 90%)"
  combiner     = "OR"
  
  conditions {
    display_name = "GPU Memory Utilization > 90%"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        resource.labels.service_name="${var.cloud_run_service_name}"
        metric.type="run.googleapis.com/container/gpu/memory/utilizations"
      EOT
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
      }
      
      comparison      = "COMPARISON_GT"
      threshold_value = 0.90
      duration        = "300s"
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = length(var.notification_channels) > 0 ? var.notification_channels : (
    var.notification_email != "" ? [google_monitoring_notification_channel.email_channel[0].id] : []
  )
  
  alert_strategy {
    auto_close = "86400s"
  }
  
  severity = "WARNING"
  
  documentation {
    content = <<-EOT
      # GPU Memory Utilization High Alert
      
      GPU memory utilization for AxiomGuard LLM service has exceeded 90%.
      
      ## Possible Causes
      - Model size too large for GPU memory
      - Concurrent requests consuming excessive memory
      - Memory leaks in the application
      - Insufficient GPU memory for the workload
      
      ## Recommended Actions
      1. Review current batch size and concurrent request settings
      2. Consider model quantization to reduce memory usage
      3. Check for memory leaks in application logs
      4. Consider upgrading to GPU with more memory
      5. Implement request throttling to limit concurrent processing
    EOT
    mime_type = "text/markdown"
  }
  
  labels = {
    service     = "axiomguard-llm"
    environment = "production"
    alert_type  = "gpu_memory"
  }
}
