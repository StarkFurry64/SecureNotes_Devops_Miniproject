# --- Availability test: Azure itself checks /health from two regions every 5 minutes -----

resource "azurerm_application_insights_standard_web_test" "health" {
  name                    = "webtest-${var.app_name}-health"
  location                = azurerm_resource_group.rg.location
  resource_group_name     = azurerm_resource_group.rg.name
  application_insights_id = azurerm_application_insights.insights.id
  geo_locations           = ["apac-sg-sin-azr", "apac-hk-hkn-azr"] # Singapore, Hong Kong
  frequency               = 300
  timeout                 = 30
  enabled                 = true
  retry_enabled           = true

  request {
    url = "https://${azurerm_container_app.app.ingress[0].fqdn}/health"
  }

  validation_rules {
    expected_status_code = 200
    ssl_check_enabled    = true

    content {
      content_match = "healthy"
    }
  }

  lifecycle {
    ignore_changes = [tags] # Azure adds a hidden-link tag to the test
  }
}

# --- Who gets told ----------------------------------------------------------------

resource "azurerm_monitor_action_group" "team" {
  name                = "ag-${var.app_name}-team"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = "securenotes"

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name                    = "email-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

# --- Alerts -------------------------------------------------------------------------

resource "azurerm_monitor_metric_alert" "app_down" {
  name                = "alert-${var.app_name}-down"
  resource_group_name = azurerm_resource_group.rg.name
  scopes = [
    azurerm_application_insights_standard_web_test.health.id,
    azurerm_application_insights.insights.id,
  ]
  description   = "SecureNotes /health is failing from at least one test location."
  severity      = 1
  frequency     = "PT1M"
  window_size   = "PT5M"
  auto_mitigate = true

  application_insights_web_test_location_availability_criteria {
    web_test_id           = azurerm_application_insights_standard_web_test.health.id
    component_id          = azurerm_application_insights.insights.id
    failed_location_count = 1
  }

  action {
    action_group_id = azurerm_monitor_action_group.team.id
  }
}

resource "azurerm_monitor_metric_alert" "failed_requests" {
  name                = "alert-${var.app_name}-failed-requests"
  resource_group_name = azurerm_resource_group.rg.name
  scopes              = [azurerm_application_insights.insights.id]
  description         = "More than 20 failed requests (HTTP 4xx/5xx) in 5 minutes."
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true

  criteria {
    metric_namespace = "microsoft.insights/components"
    metric_name      = "requests/failed"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 20
  }

  action {
    action_group_id = azurerm_monitor_action_group.team.id
  }
}

# --- Cost guard -------------------------------------------------------------------

resource "azurerm_consumption_budget_resource_group" "budget" {
  count             = var.enable_budget ? 1 : 0
  name              = "budget-${var.app_name}"
  resource_group_id = azurerm_resource_group.rg.id
  amount            = var.budget_amount
  time_grain        = "Monthly"

  time_period {
    start_date = var.budget_start_date
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = var.alert_emails
  }

  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    contact_emails = var.alert_emails
  }
}
