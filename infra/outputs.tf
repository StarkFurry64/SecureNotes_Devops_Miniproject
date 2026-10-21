output "app_url" {
  description = "Live URL of SecureNotes."
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

output "health_url" {
  description = "Health endpoint checked by the pipeline and the availability test."
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}/health"
}

output "dashboard_url" {
  description = "The SecureNotes operations dashboard (Azure Monitor workbook)."
  value       = "https://portal.azure.com/#@${data.azurerm_client_config.current.tenant_id}/resource${azurerm_application_insights_workbook.dashboard.id}/workbook"
}

output "live_metrics_url" {
  description = "Application Insights Live Metrics (updates every second)."
  value       = "https://portal.azure.com/#@${data.azurerm_client_config.current.tenant_id}/resource${azurerm_application_insights.insights.id}/quickPulse"
}

output "github_secrets" {
  description = "Add these three as GitHub repository secrets so the pipeline can deploy (they are IDs, not passwords)."
  value = {
    AZURE_CLIENT_ID       = azurerm_user_assigned_identity.github_deploy.client_id
    AZURE_TENANT_ID       = data.azurerm_client_config.current.tenant_id
    AZURE_SUBSCRIPTION_ID = data.azurerm_client_config.current.subscription_id
  }
}
