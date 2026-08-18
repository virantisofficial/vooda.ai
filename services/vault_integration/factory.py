# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Factory for creating vault provider instances."""

from services.vault_integration.base import VaultProviderBase


def create_vault_provider(provider: str, config: dict) -> VaultProviderBase:
    if provider == "hashicorp_vault":
        from services.vault_integration.hashicorp import HashiCorpVaultProvider
        return HashiCorpVaultProvider(config)
    elif provider == "aws_secrets_manager":
        from services.vault_integration.aws_sm import AWSSecretsManagerProvider
        return AWSSecretsManagerProvider(config)
    elif provider == "azure_key_vault":
        from services.vault_integration.azure_kv import AzureKeyVaultProvider
        return AzureKeyVaultProvider(config)
    elif provider == "gcp_secret_manager":
        from services.vault_integration.gcp_sm import GCPSecretManagerProvider
        return GCPSecretManagerProvider(config)
    elif provider == "cyberark":
        from services.vault_integration.cyberark import CyberArkProvider
        return CyberArkProvider(config)
    else:
        raise ValueError(f"Unsupported vault provider: {provider}")


#: Providers this module can construct. The integrations registry in
#: ``apps/api/app/routers/integrations.py`` must stay in step with this
#: list — a provider advertised there but missing here is exactly the
#: defect that made every vault Configure button return 400.
VAULT_PROVIDERS = (
    "hashicorp_vault",
    "aws_secrets_manager",
    "azure_key_vault",
    "gcp_secret_manager",
    "cyberark",
)
