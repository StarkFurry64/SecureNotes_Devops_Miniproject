# GitHub Actions deploys with OpenID Connect: GitHub proves "I am the production job of
# this repository" and Azure hands out a short-lived token. No Azure password is stored anywhere.

resource "azurerm_user_assigned_identity" "github_deploy" {
  name                = "id-${var.app_name}-github"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_federated_identity_credential" "github_production" {
  name      = "github-production"
  parent_id = azurerm_user_assigned_identity.github_deploy.id
  audience  = ["api://AzureADTokenExchange"]
  issuer    = "https://token.actions.githubusercontent.com"
  subject   = "repo:${var.github_repository}:environment:production"
}

# Least privilege: the identity can change resources in this one resource group only.
resource "azurerm_role_assignment" "github_deploy" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.github_deploy.principal_id
}
