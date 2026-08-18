# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Migration Assistant — generates scripts to move hardcoded secrets to vault."""

import structlog
from dataclasses import dataclass

logger = structlog.get_logger()


@dataclass
class MigrationScript:
    nhi_name: str
    file_path: str
    provider: str
    vault_provider: str
    vault_path: str
    before_code: str
    after_code: str
    cli_commands: list[str]
    instructions: list[str]


def generate_migration(
    secret_type: str,
    file_path: str,
    variable_name: str,
    vault_provider: str,
    vault_path: str,
) -> MigrationScript:
    """Generate migration script to move a hardcoded secret into a vault."""

    # Detect language from file extension
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    before_code = ""
    after_code = ""
    cli_commands = []
    instructions = []

    if vault_provider == "hashicorp_vault":
        cli_commands = [
            f"# Store secret in Vault",
            f"vault kv put secret/{vault_path} value='<YOUR_SECRET_VALUE>'",
            f"",
            f"# Verify",
            f"vault kv get secret/{vault_path}",
        ]

        if ext == "py":
            before_code = f'{variable_name} = "sk_live_xxxxx..."'
            after_code = f"""import hvac\nclient = hvac.Client(url=os.environ['VAULT_ADDR'], token=os.environ['VAULT_TOKEN'])\n{variable_name} = client.secrets.kv.v2.read_secret_version(path='{vault_path}')['data']['data']['value']"""
        elif ext in ("js", "ts"):
            before_code = f'const {variable_name} = "sk_live_xxxxx..."'
            after_code = f"const {variable_name} = await vault.read('secret/data/{vault_path}').then(r => r.data.data.value)"
        else:
            before_code = f'{variable_name} = "sk_live_xxxxx..."'
            after_code = f'{variable_name} = $VAULT_SECRET_{vault_path.upper().replace("/", "_")}'

    elif vault_provider == "aws_secrets_manager":
        cli_commands = [
            f"# Store in AWS Secrets Manager",
            f"aws secretsmanager create-secret --name {vault_path} --secret-string '<YOUR_SECRET>'",
            f"",
            f"# Or update existing",
            f"aws secretsmanager put-secret-value --secret-id {vault_path} --secret-string '<YOUR_SECRET>'",
        ]

        if ext == "py":
            before_code = f'{variable_name} = "sk_live_xxxxx..."'
            after_code = f"""import boto3\nclient = boto3.client('secretsmanager')\n{variable_name} = client.get_secret_value(SecretId='{vault_path}')['SecretString']"""
        elif ext in ("js", "ts"):
            before_code = f'const {variable_name} = "sk_live_xxxxx..."'
            after_code = f"""const {{ SecretsManagerClient, GetSecretValueCommand }} = require('@aws-sdk/client-secrets-manager');\nconst {variable_name} = (await new SecretsManagerClient().send(new GetSecretValueCommand({{ SecretId: '{vault_path}' }}))).SecretString;"""

    elif vault_provider == "azure_key_vault":
        cli_commands = [
            f"# Store in Azure Key Vault",
            f"az keyvault secret set --vault-name <YOUR_VAULT> --name {vault_path} --value '<YOUR_SECRET>'",
        ]

        if ext == "py":
            before_code = f'{variable_name} = "sk_live_xxxxx..."'
            after_code = f"""from azure.identity import DefaultAzureCredential\nfrom azure.keyvault.secrets import SecretClient\nclient = SecretClient(vault_url=os.environ['AZURE_VAULT_URL'], credential=DefaultAzureCredential())\n{variable_name} = client.get_secret('{vault_path}').value"""

    instructions = [
        f"1. Store the secret value in {vault_provider.replace('_', ' ').title()}",
        f"2. Replace the hardcoded value in {file_path} with the vault lookup code",
        f"3. Add vault connection config to environment variables",
        f"4. Test that the application can read the secret from vault",
        f"5. Remove the old hardcoded value and commit",
        f"6. Verify in production before removing any fallbacks",
    ]

    return MigrationScript(
        nhi_name=variable_name,
        file_path=file_path,
        provider=secret_type,
        vault_provider=vault_provider,
        vault_path=vault_path,
        before_code=before_code,
        after_code=after_code,
        cli_commands=cli_commands,
        instructions=instructions,
    )
