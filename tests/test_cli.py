import json
import pytest
import requests
from unittest.mock import MagicMock, ANY

from click.testing import CliRunner
from zalando_deploy_cli.cli import cli


@pytest.fixture
def mock_config(monkeypatch):
    config = {
        'kubernetes_api_server': 'https://example.org',
        'kubernetes_cluster': 'mycluster',
        'kubernetes_namespace': 'mynamespace'
    }
    monkeypatch.setattr('stups_cli.config.load_config', MagicMock(return_value=config))


def test_switch_deployment(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', 'deployments', '--namespace=mynamespace',
                       '-l', 'application=myapp', '-o', 'json']
        output = {
            'items': [
                {'metadata': {'name': 'myapp-v3-r40'}},
                {'metadata': {'name': 'myapp-v2-r41'}},
                {'metadata': {'name': 'myapp-v2-r42'}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    result = runner.invoke(cli, ['switch-deployment', 'myapp', 'v2', 'r42', '1/2'])
    assert ('Scaling deployment myapp-v3-r40 to 1 replicas..\n'
            'Scaling deployment myapp-v2-r42 to 1 replicas..\n'
            'Scaling deployment myapp-v2-r41 to 0 replicas..\n'
            'my-change-request-id' == result.output.strip())


def test_switch_deployment_call_once(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', 'deployments', '--namespace=mynamespace',
                       '-l', 'application=myapp', '-o', 'json']
        output = {
            'items': [
                {'metadata': {'name': 'myapp-v3-r40'}},
                {'metadata': {'name': 'myapp-v2-r41'}},
                {'metadata': {'name': 'myapp-v2-r42'}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    result = runner.invoke(cli, ['switch-deployment', 'myapp', 'v2', 'r42', '1/2'])

    request.called_once_with(requests.patch,
                             ('https://example.org/kubernetes-clusters/'
                              'mycluster/namespaces/mynamespace/resources'),
                             json={'resources_update': ANY})
    assert result.exit_code == 0


def test_switch_deployment_target_does_not_exist(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', 'deployments', '--namespace=mynamespace',
                       '-l', 'application=myapp', '-o', 'json']
        output = {
            'items': [
                {'metadata': {'name': 'myapp-v3-r40'}},
                {'metadata': {'name': 'myapp-v2-r41'}},
                {'metadata': {'name': 'myapp-v2-r43'}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    result = runner.invoke(cli, ['switch-deployment', 'myapp', 'v2', 'r42', '1/2'])
    assert 'Deployment myapp-v2-r42 does not exist!' in result.output
    assert result.exit_code == 1


def test_delete_old_deployments(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', 'deployments', '--namespace=mynamespace', '-l',
                       'application=myapp', '-o', 'json']
        output = {
            'items': [
                {'metadata': {'name': 'myapp-v2-r40'}},
                {'metadata': {'name': 'myapp-v2-r41'}},
                {'metadata': {'name': 'myapp-v2-r42'}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    result = runner.invoke(cli, ['delete-old-deployments', 'myapp', 'v2', 'r42'])
    assert ('Deleting deployment myapp-v2-r41..\n'
            'my-change-request-id\n'
            'Deleting deployment myapp-v2-r40..\n'
            'my-change-request-id' == result.output.strip())
