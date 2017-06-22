import botocore.exceptions
import json
import pytest
import requests
import yaml
import zalando_deploy_cli.cli
from unittest.mock import MagicMock, ANY

from click.testing import CliRunner
from zalando_deploy_cli.cli import (cli,
                                    get_aws_account_name,
                                    get_replicas,
                                    get_owned_replicasets,
                                    delete_deployment,
                                    get_prev_release,
                                    calculate_backend_weights,
                                    INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY,
                                    get_ingress_backends)


@pytest.fixture
def mock_config(monkeypatch):
    config = {
        'kubernetes_api_server': 'https://example.org',
        'kubernetes_cluster': 'mycluster',
        'kubernetes_namespace': 'mynamespace',
        'deploy_api': 'https://deploy.example.org'
    }
    load_config = MagicMock(return_value=config)
    monkeypatch.setattr('stups_cli.config.load_config', load_config)
    return load_config


def test_create_deployment_invalid_argument():
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('template.yaml', 'w') as fd:
            yaml.dump({}, fd)

        result = runner.invoke(cli, ['create-deployment', 'template.yaml', 'my-app2', 'v2-X', 'r42'])
    assert 'Error: Invalid value for "version": does not match regular expression pattern "^[a-z0-9][a-z0-9.-]*$' in result.output


def test_create_deployment_success(monkeypatch):
    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-cr-id'}
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('template.yaml', 'w') as fd:
            yaml.dump({}, fd)

        result = runner.invoke(cli, ['create-deployment', 'template.yaml', 'my-app', 'v1', 'r1', 'replicas=3'])
    assert 'my-cr-id' == result.output.strip()


def test_apply(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'services',
                       '-l', 'application=myapp']
        output = {
            'items': [
                {'metadata': {'name': 'myapp-r40', 'labels': {'application': 'myapp'}}},
                {'metadata': {'name': 'myapp-r41', 'labels': {'application': 'myapp'}}},
                {'metadata': {'name': 'myapp-r42', 'labels': {'application': 'myapp'}}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    def _render_template(fd, context):
        assert context["release"] == "2"
        return {"kind": "Service"}

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('zalando_deploy_cli.cli._render_template', _render_template)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('manifest.yaml', 'w') as f:
            f.write("apiVersion: v1\nkind: Pod")

        result = runner.invoke(cli, ['apply', 'manifest.yaml', 'replicas=1', 'application=myapp',
                                'release=2', 'version=v1.0'])
        assert ('Applying Kubernetes manifest manifest.yaml..\n'
                'my-change-request-id' == result.output.strip())
        assert result.exception == None


def test_switch_deployment(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'deployments',
                       '-l', 'application=myapp']
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
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'deployments',
                       '-l', 'application=myapp']
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
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'deployments',
                       '-l', 'application=myapp']
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


def test_scale_deployment(monkeypatch, mock_config):
    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)

    runner = CliRunner()
    result = runner.invoke(cli, ['scale-deployment', 'myapp', 'v2', 'r42', '1'])
    assert ('Scaling deployment myapp-v2-r42 to 1 replicas..\n'
            'my-change-request-id' == result.output.strip())


def test_traffic(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'ingresses',
                       'myapp']
        output = {'metadata': {'name': 'myapp-v2-r40'}}

        return json.dumps(output).encode('utf-8')

    def calculate_backend_weights(ingress, backend, percent):
        return {backend: percent}

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_login', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('zalando_deploy_cli.cli.calculate_backend_weights', calculate_backend_weights)
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    result = runner.invoke(cli, ['traffic', 'myapp', '2', '20'])
    assert result.exception == None
    assert ('my-change-request-id' == result.output.strip())


def test_calculate_backend_weights(monkeypatch):
    test_cases = [
            {
                'percent': 100,
                'backend': 'a',
                'ingress': {
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}}
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 100}
            },
            {
                'percent': 30,
                'backend': 'a',
                'ingress': {
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}},
                                        {'backend': {'serviceName': 'b'}},
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 30, 'b': 70}
            },
    ]

    for tc in test_cases:
        weights = calculate_backend_weights(tc['ingress'], tc['backend'], tc['percent'])
        assert weights == tc['expected']


def test_get_ingress_backends(monkeypatch):
    test_cases = [
            {
                'ingress': {
                    'metadata': {
                        'annotations': {
                            INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY: '{"a":30}',
                        },
                    },
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}}
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 100}
            },
            {
                'ingress': {
                    'metadata': {
                        'annotations': {
                            INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY: '{"a":30}',
                        },
                    },
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}},
                                        {'backend': {'serviceName': 'b'}}
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 100, 'b': 0}
            },
            {
                'ingress': {
                    'metadata': {
                        'annotations': {
                            INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY: '{"a":30, "b": 70}',
                        },
                    },
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}},
                                        {'backend': {'serviceName': 'b'}},
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 30, 'b': 70}
            },
            {
                'ingress': {
                    'metadata': {},
                    'spec': {
                        'rules': [
                            {
                                'http': {
                                    'paths': [
                                        {'backend': {'serviceName': 'a'}},
                                        {'backend': {'serviceName': 'b'}},
                                    ]
                                }
                            }
                        ]
                    }
                },
                'expected': {'a': 50, 'b': 50}
            },
    ]

    for tc in test_cases:
        weights = get_ingress_backends(tc['ingress'])
        assert weights == tc['expected']


def test_delete_old_deployments(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'deployments', '-l',
                       'application=myapp']
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
    monkeypatch.setattr('zalando_deploy_cli.cli.delete_deployment', MagicMock())
    monkeypatch.setattr('subprocess.check_output', check_output)

    runner = CliRunner()
    runner.invoke(cli, ['delete-old-deployments', 'myapp', 'v2', 'r42'])


def test_get_replicas(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'deployments', 'mydeployment']
        output = {'status': {'replicas': 0}}
        return json.dumps(output).encode('utf-8')

    monkeypatch.setattr('subprocess.check_output', check_output)

    assert get_replicas('mydeployment', 'mynamespace') == 0


def test_get_owned_replicasets(monkeypatch, mock_config):
    deployment = {'metadata': {'uid': 'id'}}
    replicasets = [
        {'metadata': {'ownerReferences': [{'uid': 'id'}]}},
        {'metadata': {}},
    ]

    assert get_owned_replicasets(deployment, replicasets) == [{'metadata': {'ownerReferences': [{'uid': 'id'}]}}]


def test_delete(monkeypatch, mock_config):
    def kubectl_get(namespace, *args):
        if args[0] == 'replicasets':
            output = {
                'items': [
                    {'metadata': {
                        'ownerReferences': [{'uid': 'id'}],
                        'name': 'myreplicasets',
                    }},
                    {'metadata': {'name': 'myotherreplicasets'}},
                ]
            }
        elif args[0] == 'deployments':
            output = {
                'metadata': {
                    'uid': 'id',
                    'name': 'mydeployment',
                    'namespace': 'mynamespace',
                },
            }
        return output

    def get_replicas(name, namespace):
        return 0

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('zalando_deploy_cli.cli._scale_deployment', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.get_replicas', get_replicas)
    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_get', kubectl_get)

    runner = CliRunner()
    result = runner.invoke(cli, ['delete', 'kubernetes', 'deployments/myapp'])
    assert result.exception == None


def test_delete_deployment(monkeypatch, mock_config):
    def check_output(cmd):
        assert cmd == ['zkubectl', 'get', '--namespace=mynamespace', '-o', 'json', 'replicasets']
        output = {
            'items': [
                {'metadata': {
                    'ownerReferences': [{'uid': 'id'}],
                    'name': 'myreplicasets',
                }},
                {'metadata': {'name': 'myotherreplicasets'}},
            ]
        }
        return json.dumps(output).encode('utf-8')

    def get_replicas(name, namespace):
        return 0

    deployment = {
        'metadata': {
            'uid': 'id',
            'name': 'mydeployment',
            'namespace': 'mynamespace',
        },
    }

    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)
    monkeypatch.setattr('zalando_deploy_cli.cli._scale_deployment', MagicMock())
    monkeypatch.setattr('zalando_deploy_cli.cli.get_replicas', get_replicas)
    monkeypatch.setattr('subprocess.check_output', check_output)

    delete_deployment(mock_config, deployment, True)


def test_promote_deployment(monkeypatch, mock_config):
    request = MagicMock()
    request.return_value.json.return_value = {'id': 'my-change-request-id'}

    monkeypatch.setattr('zalando_deploy_cli.cli.request', request)

    runner = CliRunner()
    result = runner.invoke(cli, ['promote-deployment', 'myapp', 'v2', 'r42', 'production'])
    assert 'Promoting deployment myapp-v2-r42 to production stage..\nmy-change-request-id' == result.output.strip()


def test_request_exit_on_error(monkeypatch, capsys):
    monkeypatch.setattr('zign.api.get_token', lambda a, b: 'mytok')

    mock_get = MagicMock()
    mock_get.return_value.status_code = 418
    mock_get.return_value.text = 'Some Error'

    with pytest.raises(SystemExit):
        zalando_deploy_cli.cli.request({}, mock_get, 'https://example.org')
    out, err = capsys.readouterr()
    assert 'Server returned HTTP error 418 for https://example.org:\nSome Error' == err.strip()


def test_request_headers(monkeypatch, capsys):
    monkeypatch.setattr('zign.api.get_token', lambda a, b: 'mytok')

    def mock_get(*args, **kwargs):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = kwargs.get('headers')
        return response

    response = zalando_deploy_cli.cli.request({'user': 'jdoe'}, mock_get, 'https://example.org')
    assert {'Authorization': 'Bearer mytok', 'X-On-Behalf-Of': 'jdoe'} == response.json()


def test_get_current_replicas(monkeypatch, mock_config):
    kubectl_get = MagicMock()
    kubectl_get.return_value = {'items': [{'status': {'replicas': 1}}, {'status': {'replicas': 2}}]}
    monkeypatch.setattr('zalando_deploy_cli.cli.kubectl_get', kubectl_get)

    runner = CliRunner()
    result = runner.invoke(cli, ['get-current-replicas', 'myapp'])
    assert '3' == result.output.strip()


def test_get_aws_account_name(monkeypatch):
    zaws_config = {
        "last_update": {'account_name': 'test'}
    }
    load_config = MagicMock(return_value=zaws_config)
    monkeypatch.setattr('stups_cli.config.load_config', load_config)
    assert get_aws_account_name() == 'test'

    load_config.return_value = {}
    assert get_aws_account_name() == "unknown-account"


def test_encrypt(monkeypatch, mock_config):
    encrypt_call = MagicMock()
    encrypt_call.return_value = encrypt_call
    encrypt_call.json = MagicMock(return_value={
        'data': 'barFooBAR='
    })
    monkeypatch.setattr('zalando_deploy_cli.cli.request', encrypt_call)

    monkeypatch.setattr('zalando_deploy_cli.cli.get_aws_account_name',
                        MagicMock(return_value="test"))

    mock_exit = MagicMock()
    monkeypatch.setattr('sys.exit',
                        mock_exit)

    mock_boto = MagicMock()
    mock_boto.return_value = mock_boto
    mock_boto.encrypt = MagicMock(return_value={'CiphertextBlob': b'test'})
    monkeypatch.setattr('boto3.client', mock_boto)

    runner = CliRunner()
    result = runner.invoke(cli, ['encrypt', '--use-kms'], input='my_secret')
    assert 'deployment-secret:test:dGVzdA==' == result.output.strip()

    mock_boto.encrypt.side_effect = botocore.exceptions.ClientError(
        operation_name="test",
        error_response={"Error": {"Code": "test"}}
    )

    result = runner.invoke(cli, ['encrypt', '--use-kms'], input='my_secret')
    assert 'Failed to encrypt with KMS' == result.output.strip()

    mock_boto.encrypt.side_effect = botocore.exceptions.ClientError(
        operation_name="test",
        error_response={"Error": {"Code": "NotFoundException"}}
    )

    result = runner.invoke(cli, ['encrypt', '--use-kms'], input='my_secret')
    assert "KMS key 'deployment-secret' not found" == result.output.strip()

    mock_boto.encrypt.side_effect = botocore.exceptions.ClientError(
        operation_name="test",
        error_response={"Error": {"Code": "ExpiredTokenException"}}
    )

    result = runner.invoke(cli, ['encrypt', '--use-kms'], input='my_secret')
    assert "Not logged in to AWS" == result.output.strip()

    result = runner.invoke(cli, ['encrypt'], input='my_secret')
    encrypted = result.output.strip()
    assert "deployment-secret:autobahn-encrypted:barFooBAR=" == encrypted


    encrypt_call.assert_called_with(mock_config(), requests.post,
                                    mock_config().get('deploy_api') + '/secrets',
                                    json={'plaintext': 'my_secret'})


def test_resolve_version(monkeypatch):
    monkeypatch.setattr('zign.api.get_token', lambda a, b: 'mytok')
    monkeypatch.setattr('pierone.api.get_latest_tag', lambda a, b: 'cd123')
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('template.yaml', 'w') as fd:
            yaml.dump({'spec': {'template': {'spec': {'containers': [{'image': 'myregistry.example.org/foo/bar:{{version}}'}]}}}}, fd)
        result = runner.invoke(cli, ['resolve-version', 'template.yaml', 'my-app', 'latest', 'r1', 'replicas=3'], catch_exceptions=False)
        print(result)
    assert 'cd123' == result.output.strip()


def test_get_prev_release(monkeypatch):
    services = [
                {'metadata': {'name': 'myapp-r40', 'labels': {'application': 'myapp', 'release': '2'}}},
            ]
    assert '2' == get_prev_release(services, "1")
