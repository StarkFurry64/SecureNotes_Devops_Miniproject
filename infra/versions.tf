terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
  # State stays local for this project (it is git-ignored because it contains secrets).
  # A team setup would keep it in an Azure Storage account backend instead.
}

provider "azurerm" {
  features {}
  # The subscription comes from ARM_SUBSCRIPTION_ID or `az account show`.
  # Providers were registered once by hand, so Terraform does not try to register everything.
  resource_provider_registrations = "none"
}
