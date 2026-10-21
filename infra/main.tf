data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
  tags = {
    project = "securenotes"
    purpose = "devops-lab-ia"
  }
}

# --- Logs and telemetry ------------------------------------------------------

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-${var.app_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 1 # hard cap on ingestion, so a mistake cannot burn the credit
}

resource "azurerm_application_insights" "insights" {
  name                = "appi-${var.app_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  workspace_id        = azurerm_log_analytics_workspace.logs.id
  application_type    = "web"
}

# --- Hosting -------------------------------------------------------------------

resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${var.app_name}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
}

resource "random_password" "app_secret" {
  length  = 48
  special = false
}

resource "azurerm_container_app" "app" {
  name                         = var.app_name
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  secret {
    name  = "app-secret-key"
    value = random_password.app_secret.result
  }

  secret {
    name  = "appinsights-connection-string"
    value = azurerm_application_insights.insights.connection_string
  }

  secret {
    name  = "dockerhub-token"
    value = var.dockerhub_token
  }

  registry {
    server               = "docker.io"
    username             = var.dockerhub_username
    password_secret_name = "dockerhub-token"
  }

  ingress {
    external_enabled = true
    target_port      = 5000
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    # Notes live in memory, so exactly one replica keeps every visitor on the same list.
    min_replicas = 1
    max_replicas = 1

    container {
      name   = var.app_name
      image  = var.image
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "APP_SECRET_KEY"
        secret_name = "app-secret-key"
      }

      env {
        name        = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        secret_name = "appinsights-connection-string"
      }

      env {
        name  = "OTEL_SERVICE_NAME"
        value = var.app_name
      }

      # Self-healing: Azure restarts the container if /health stops answering.
      liveness_probe {
        transport               = "HTTP"
        port                    = 5000
        path                    = "/health"
        interval_seconds        = 10
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = 5000
        path                    = "/health"
        interval_seconds        = 10
        failure_count_threshold = 3
      }
    }
  }

  lifecycle {
    # The CI/CD pipeline rolls out each new image; Terraform only creates the app.
    ignore_changes = [
      template[0].container[0].image,
      template[0].revision_suffix,
    ]
  }
}
