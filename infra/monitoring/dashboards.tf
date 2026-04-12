# Google Cloud Monitoring Dashboard for AxiomGuard Cloud Run GPU Service

resource "google_monitoring_dashboard" "axiomguard_latency_dashboard" {
  dashboard_json = jsonencode({
    displayName = "AxiomGuard LLM Service - Latency & Performance"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          title = "Request Latency (p50, p95, p99)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/request_latencies"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_PERCENTILE_50"
                    }
                  }
                }
                plotType = "LINE"
                legendTemplate = "p50"
              },
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/request_latencies"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_PERCENTILE_95"
                    }
                  }
                }
                plotType = "LINE"
                legendTemplate = "p95"
              },
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/request_latencies"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_PERCENTILE_99"
                    }
                  }
                }
                plotType = "LINE"
                legendTemplate = "p99"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Latency (ms)"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "Request Count"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/request_count"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_RATE"
                      groupByFields = [
                        "metric.label.response_code"
                      ]
                    }
                  }
                }
                plotType = "STACKED_BAR"
                minAlignmentPeriod = "60s"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Requests/sec"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "Error Rate (%)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilterRatio = {
                    numerator = {
                      filter = <<-EOT
                        resource.type="cloud_run_revision"
                        resource.labels.service_name="${var.cloud_run_service_name}"
                        metric.type="run.googleapis.com/request_count"
                        metric.label.response_code_class="5xx"
                      EOT
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_RATE"
                      }
                    }
                    denominator = {
                      filter = <<-EOT
                        resource.type="cloud_run_revision"
                        resource.labels.service_name="${var.cloud_run_service_name}"
                        metric.type="run.googleapis.com/request_count"
                      EOT
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_RATE"
                      }
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Error Rate (%)"
              scale = "LINEAR"
            }
            chartOptions = {
              mode = "COLOR"
            }
          }
        },
        {
          title = "Active Instances"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/container/instance_count"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                    }
                  }
                }
                plotType = "LINE"
                minAlignmentPeriod = "60s"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Instance Count"
              scale = "LINEAR"
            }
          }
        }
      ]
    }
  })
}

# GPU Metrics Dashboard
resource "google_monitoring_dashboard" "axiomguard_gpu_dashboard" {
  dashboard_json = jsonencode({
    displayName = "AxiomGuard LLM Service - GPU Metrics"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          title = "GPU Utilization (%)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/container/gpu/utilizations"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "GPU Utilization (%)"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "GPU Memory Utilization (%)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/container/gpu/memory/utilizations"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "GPU Memory (%)"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "CPU Utilization (%)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/container/cpu/utilizations"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "CPU Utilization (%)"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "Memory Utilization (%)"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = <<-EOT
                      resource.type="cloud_run_revision"
                      resource.labels.service_name="${var.cloud_run_service_name}"
                      metric.type="run.googleapis.com/container/memory/utilizations"
                    EOT
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_MEAN"
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Memory Utilization (%)"
              scale = "LINEAR"
            }
          }
        }
      ]
    }
  })
}
