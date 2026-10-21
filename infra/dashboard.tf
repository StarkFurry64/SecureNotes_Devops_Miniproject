# The SecureNotes operations dashboard, defined as code (an Azure Monitor workbook).
# Each panel is a KQL query over the telemetry the app sends to Application Insights.

resource "random_uuid" "dashboard" {}

locals {
  window = "ago(1h)"

  panels = [
    {
      title = "Requests per minute"
      query = "requests | where timestamp > ${local.window} | summarize Requests = sum(itemCount) by bin(timestamp, 1m) | render timechart"
      chart = "timechart"
    },
    {
      title = "Response time (ms): average and 95th percentile"
      query = "requests | where timestamp > ${local.window} | summarize Average = avg(duration), P95 = percentile(duration, 95) by bin(timestamp, 1m) | render timechart"
      chart = "timechart"
    },
    {
      title = "Failed requests by status code"
      query = "requests | where timestamp > ${local.window} and success == false | summarize Failed = sum(itemCount) by bin(timestamp, 1m), resultCode | render timechart"
      chart = "timechart"
    },
    {
      title = "Availability from Azure test locations (%)"
      query = "availabilityResults | where timestamp > ago(24h) | summarize Availability = 100.0 * avg(todouble(success)) by bin(timestamp, 5m), location | render timechart"
      chart = "timechart"
    },
    {
      title = "Notes created (business metric)"
      query = "customMetrics | where timestamp > ${local.window} and name == 'notes_created' | summarize Notes = sum(valueSum) by bin(timestamp, 1m) | render columnchart"
      chart = "barchart"
    },
    {
      title = "Last hour at a glance"
      query = "requests | where timestamp > ${local.window} | summarize Requests = sum(itemCount), Failed = sumif(itemCount, success == false), ['Avg ms'] = round(avg(duration), 1), ['P95 ms'] = round(percentile(duration, 95), 1)"
      chart = "table"
    },
  ]
}

resource "azurerm_application_insights_workbook" "dashboard" {
  name                = random_uuid.dashboard.result
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  display_name        = "SecureNotes - Operations Dashboard"
  source_id           = lower(azurerm_application_insights.insights.id)
  category            = "workbook"

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = concat(
      [{
        type = 1
        name = "header"
        content = {
          json = "## SecureNotes - live operations\nTraffic, speed, failures and availability for the app running on Azure Container Apps. For second-by-second data open **Live Metrics** in Application Insights."
        }
      }],
      [for index, panel in local.panels : {
        type = 3
        name = "panel-${index}"
        content = {
          version       = "KqlItem/1.0"
          title         = panel.title
          query         = panel.query
          size          = 0
          queryType     = 0
          resourceType  = "microsoft.insights/components"
          visualization = panel.chart
        }
        customWidth = "50"
      }]
    )
    "$schema" = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
  })
}
