import base64

import json
import os
import re
import string
import subprocess
import sys
import textwrap
import time
import urllib.parse
import errno
from pathlib import Path

import boto3
import botocore.exceptions as boto_exceptions
import click
import pierone.api
import pystache
import requests
import stups_cli.config
import yaml
import zign.api
from clickclick import Action, AliasedGroup, error, info, print_table


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

# NOTE: application-version-release will be used as Kubernetes resource name
# Kubernetes resource names must conform to DNS_SUBDOMAIN
# see https://github.com/kubernetes/kubernetes/blob/1dfd64f4378ad9dd974bbfbef8e90127dce6aafe/pkg/api/v1/types.go#L53
APPLICATION_PATTERN = re.compile('^[a-z][a-z0-9-]*$')
VERSION_PATTERN = re.compile('^[a-z0-9][a-z0-9.-]*$')

INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY = 'zalando.org/backend-weights'

DEFAULT_HTTP_TIMEOUT = 30  # seconds
DEFAULT_RESOURCE_DELETION_TIMEOUT = 30  # seconds

# EC2 instance memory in MiB
EC2_INSTANCE_MEMORY = {
    't2.nano': 500,
    't2.micro': 1000,
    't2.small': 2000,
    't2.medium': 4000,
    'm3.medium': 3750,
    'm4.large': 8000,
    'c4.large': 3750,
    'c4.xlarge': 7500
}


def get_aws_account_name() -> str:

    try:
        zaws_config = stups_cli.config.load_config("zalando-aws-cli")
        current_account = zaws_config["last_update"]["account_name"]
        return current_account
    except:
        return "unknown-account"


def find_latest_docker_image_version(image):
    docker_image = pierone.api.DockerImage.parse(image)
    if not docker_image.registry:
        error('Could not resolve "latest" tag for {}: missing registry.'.format(image))
        exit(2)
    token = zign.api.get_token('uid', ['uid'])
    latest_tag = pierone.api.get_latest_tag(docker_image, token)
    if not latest_tag:
        error('Could not resolve "latest" tag for {}'.format(image))
        exit(2)
    return latest_tag


def validate_pattern(pattern):
    def validate(ctx, param, value):
        if not pattern.match(value):
            raise click.BadParameter('does not match regular expression pattern "{}"'.format(pattern.pattern))
        return value
    return validate


application_argument = click.argument('application', callback=validate_pattern(APPLICATION_PATTERN))
version_argument = click.argument('version', callback=validate_pattern(VERSION_PATTERN))
release_argument = click.argument('release', callback=validate_pattern(VERSION_PATTERN))


def request(config: dict, method, path: str, headers=None, exit_on_error=True, **kwargs):
    token = zign.api.get_token('uid', ['uid'])
    if not headers:
        headers = {}
    headers['Authorization'] = 'Bearer {}'.format(token)
    if config.get('user'):
        headers['X-On-Behalf-Of'] = config['user']
    api_url = config.get('deploy_api')
    url = urllib.parse.urljoin(api_url, path)
    response = method(url, headers=headers, timeout=DEFAULT_HTTP_TIMEOUT, **kwargs)
    if exit_on_error:
        if not (200 <= response.status_code < 400):
            error('Server returned HTTP error {} for {}:\n{}'.format(response.status_code, url, response.text))
            exit(2)
    return response


def approve(config, change_request_id):
    path = '/change-requests/{}/approvals'.format(change_request_id)
    data = {}
    request(config, requests.post, path, json=data)


def execute(config, change_request_id):
    path = '/change-requests/{}/execute'.format(change_request_id)
    request(config, requests.post, path)


def approve_and_execute(config, change_request_id):
    approve(config, change_request_id)
    execute(config, change_request_id)


def parse_parameters(parameter):
    context = {}
    for param in parameter:
        key, val = param.split('=', 1)
        context[key] = val
    return context


def _render_template(template, context):
    contents = template.read()
    rendered_contents = pystache.render(contents, context)
    data = yaml.safe_load(rendered_contents)
    return data


class ResourcesUpdate:
    def __init__(self, updates=None):
        self.resources_update = updates or []

    def set_number_of_replicas(self, name: str, replicas: int, kind: str='deployments'):
        self.resources_update.append({
            'name': name,
            'kind': kind,
            'operations': [{'op': 'replace', 'path': '/spec/replicas', 'value': replicas}]
        })

    def set_label(self, name: str, label_key: str, label_value: str, kind: str='deployments'):
        path = '/spec/template/metadata/labels/{}'.format(label_key)
        self.resources_update.append({
            'name': name,
            'kind': kind,
            'operations': [{'op': 'replace', 'path': path, 'value': label_value}]
        })

    def set_annotation(self, name: str, key: str, value: str, kind: str='deployments'):
        path = '/metadata/annotations/{}'.format(key)
        self.resources_update.append({
            'name': name,
            'kind': kind,
            'operations': [{'op': 'replace', 'path': path, 'value': value}]
        })

    def to_dict(self):
        return {'resources_update': self.resources_update}


def kubectl_login(config):
    arg = config.get('kubernetes_api_server')
    if not arg:
        # this requires zkubectl to be configured appropriately
        # with the Cluster Registry URL
        arg = config.get('kubernetes_cluster')
    subprocess.check_call(['zkubectl', 'login', arg])


def kubectl_get(namespace, *args):
    cmd = ['zkubectl', 'get', '--namespace={}'.format(namespace), '-o', 'json'] + list(args)
    out = subprocess.check_output(cmd)
    data = json.loads(out.decode('utf-8'))
    return data


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx):
    ctx.obj = stups_cli.config.load_config('zalando-deploy-cli')


@cli.command()
@click.option('--deploy-api')
@click.option('--aws-account')
@click.option('--aws-region')
@click.option('--kubernetes-api-server')
@click.option('--kubernetes-cluster')
@click.option('--kubernetes-namespace')
@click.option('--user', help='Username to use for approvals (optional)')
@click.pass_obj
def configure(config, **kwargs):
    for key, val in kwargs.items():
        if val is not None:
            config[key] = val
    stups_cli.config.store_config(config, 'zalando-deploy-cli')


@cli.command()
@click.argument('template_or_directory')
@click.argument('parameter', nargs=-1)
@click.pass_obj
@click.option('--execute', is_flag=True)
def apply(config, template_or_directory, parameter, execute):
    '''Apply CloudFormation or Kubernetes resource'''

    template_paths = []
    if os.path.isdir(template_or_directory):
        for entry in os.listdir(template_or_directory):
            if entry.endswith('.yaml') and not entry.startswith('.'):
                template_paths.append(os.path.join(template_or_directory, entry))
    else:
        template_paths.append(template_or_directory)

    context = parse_parameters(parameter)
    namespace = config.get('kubernetes_namespace')

    # try to find previous release of a service.
    data = kubectl_get(namespace, 'services', '-l', 'application={}'.format(context['application']))

    context["prev_release"] = get_prev_release(data['items'], context['release'])

    for path in template_paths:
        with open(path, 'r') as fd:
            data = _render_template(fd, context)

        if not isinstance(data, dict):
            error('Invalid YAML contents in {}'.format(path))
            raise click.Abort()

        if 'kind' in data:
            info('Applying Kubernetes manifest {}..'.format(path))
            cluster_id = config.get('kubernetes_cluster')
            namespace = config.get('kubernetes_namespace')
            path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
            response = request(config, requests.post, path, json=data)
            change_request_id = response.json()['id']
        elif 'Resources' in data:
            info('Applying Cloud Formation template {}..'.format(path))
            aws_account = config.get('aws_account')
            aws_region = config.get('aws_region')
            stack_name = data.get('Metadata', {}).get('StackName')
            if not stack_name:
                error('Cloud Formation template requires Metadata/StackName property')
                raise click.Abort()
            path = '/aws-accounts/{}/regions/{}/cloudformation-stacks/{}'.format(
                aws_account, aws_region, stack_name)
            response = request(config, requests.put, path, json=data)
            change_request_id = response.json()['id']
        else:
            error('Neither a Kubernetes manifest nor a Cloud Formation template: {}'.format(path))
            raise click.Abort()

        if execute:
            approve_and_execute(config, change_request_id)
        else:
            print(change_request_id)


@cli.command('resolve-version')
@click.argument('template', type=click.File('r'))
@application_argument
@version_argument
@release_argument
@click.argument('parameter', nargs=-1)
@click.pass_obj
def resolve_version(config, template, application, version, release, parameter):
    '''Resolve "latest" version if needed'''
    if version != 'latest':
        # return fixed version unchanged,
        # nothing to resolve
        print(version)
        return
    context = parse_parameters(parameter)
    context['application'] = application
    context['version'] = version
    context['release'] = release
    data = _render_template(template, context)
    for container in data['spec']['template']['spec']['containers']:
        image = container['image']
        if image.endswith(':latest'):
            latest_version = find_latest_docker_image_version(image)
            print(latest_version)
            return
    error('Could not resolve "latest" version: No matching container found. Please choose a version != "latest".')
    exit(2)


@cli.command('create-deployment')
@click.argument('template', type=click.File('r'))
@application_argument
@version_argument
@release_argument
@click.argument('parameter', nargs=-1)
@click.pass_obj
@click.option('--execute', is_flag=True)
def create_deployment(config, template, application, version, release, parameter, execute):
    '''Create a new Kubernetes deployment'''
    context = parse_parameters(parameter)
    context['application'] = application
    context['version'] = version
    context['release'] = release
    data = _render_template(template, context)

    cluster_id = config.get('kubernetes_cluster')
    namespace = config.get('kubernetes_namespace')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
    response = request(config, requests.post, path, json=data)
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


@cli.command('wait-for-deployment')
@application_argument
@version_argument
@release_argument
@click.option('-t', '--timeout',
              type=click.IntRange(0, 7200, clamp=True),
              metavar='SECS',
              default=300,
              help='Maximum wait time (default: 300s)')
@click.option('-i', '--interval', default=10,
              type=click.IntRange(1, 600, clamp=True),
              help='Time between checks (default: 10s)')
@click.pass_obj
def wait_for_deployment(config, application, version, release, timeout, interval):
    '''Wait for all pods to become ready'''
    namespace = config.get('kubernetes_namespace')
    kubectl_login(config)
    deployment_name = '{}-{}-{}'.format(application, version, release)
    cutoff = time.time() + timeout
    while time.time() < cutoff:
        data = kubectl_get(namespace, 'pods', '-l',
                           'application={},version={},release={}'.format(application, version, release))
        pods = data['items']
        pods_ready = 0
        for pod in pods:
            if pod['status'].get('phase') == 'Running':
                all_containers_ready = True
                for cont in pod['status'].get('containerStatuses', []):
                    if not cont.get('ready'):
                        all_containers_ready = False
                if all_containers_ready:
                    pods_ready += 1
        if pods and pods_ready >= len(pods):
            return
        info('Waiting up to {:.0f} more secs for deployment '
             '{} ({}/{} pods ready)..'.format(cutoff - time.time(), deployment_name, pods_ready, len(pods)))
        time.sleep(interval)
    raise click.Abort()


@cli.command('promote-deployment')
@application_argument
@version_argument
@release_argument
@click.argument('stage')
@click.option('--execute', is_flag=True)
@click.pass_obj
def promote_deployment(config, application, version, release, stage, execute):
    '''Promote deployment to new stage'''
    namespace = config.get('kubernetes_namespace')
    deployment_name = '{}-{}-{}'.format(application, version, release)

    info('Promoting deployment {} to {} stage..'.format(deployment_name, stage))
    cluster_id = config.get('kubernetes_cluster')
    namespace = config.get('kubernetes_namespace')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)

    resources_update = ResourcesUpdate()
    resources_update.set_label(deployment_name, 'stage', stage)
    response = request(config, requests.patch, path, json=resources_update.to_dict())
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


@cli.command('switch-deployment')
@application_argument
@version_argument
@release_argument
@click.argument('ratio')
@click.pass_obj
@click.option('--execute', is_flag=True)
def switch_deployment(config, application, version, release, ratio, execute):
    '''Switch to new release'''
    namespace = config.get('kubernetes_namespace')
    kubectl_login(config)

    target_replicas, total = ratio.split('/')
    target_replicas = int(target_replicas)
    total = int(total)

    data = kubectl_get(namespace, 'deployments', '-l', 'application={}'.format(application))
    deployments = data['items']
    target_deployment_name = '{}-{}-{}'.format(application, version, release)

    target_deployment_exists = False
    for deployment in deployments:
        if deployment['metadata']['name'] == target_deployment_name:
            target_deployment_exists = True
    if not target_deployment_exists:
        error("Deployment {} does not exist!".format(target_deployment_name))
        exit(1)

    resources_update = ResourcesUpdate()
    remaining_replicas = total - target_replicas
    for deployment in sorted(deployments, key=lambda d: d['metadata']['name'], reverse=True):
        deployment_name = deployment['metadata']['name']
        if deployment_name == target_deployment_name:
            replicas = target_replicas
        else:
            # maybe spread across all other deployments?
            replicas = remaining_replicas
            remaining_replicas = 0

        info('Scaling deployment {} to {} replicas..'.format(deployment_name, replicas))
        resources_update.set_number_of_replicas(deployment_name, replicas)

    cluster_id = config.get('kubernetes_cluster')
    namespace = config.get('kubernetes_namespace')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
    response = request(config, requests.patch, path, json=resources_update.to_dict())
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


@cli.command('get-current-replicas')
@application_argument
@click.pass_obj
def get_current_replicas(config, application):
    '''Get current total number of replicas for given application'''
    namespace = config.get('kubernetes_namespace')
    data = kubectl_get(namespace, 'deployments', '-l', 'application={}'.format(application))
    replicas = 0
    for deployment in data['items']:
        replicas += deployment.get('status', {}).get('replicas', 0)
    print(replicas)


@cli.command('scale-deployment')
@application_argument
@version_argument
@release_argument
@click.argument('replicas', type=int)
@click.pass_obj
@click.option('--execute', is_flag=True)
def scale_deployment(config, application, version, release, replicas, execute):
    '''Scale a single deployment'''
    kubectl_login(config)
    namespace = config.get('kubernetes_namespace')
    name = '{}-{}-{}'.format(application, version, release)
    _scale_deployment(config, name, namespace, replicas, execute)


def _scale_deployment(config, name, namespace, replicas, execute):
    '''Scale a single deployment'''
    info('Scaling deployment {} to {} replicas..'.format(name, replicas))
    resources_update = ResourcesUpdate()
    resources_update.set_number_of_replicas(name, replicas)

    cluster_id = config.get('kubernetes_cluster')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
    response = request(config, requests.patch, path, json=resources_update.to_dict())
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


@cli.command('apply-autoscaling')
@click.argument('template', type=click.File('r'))
@application_argument
@version_argument
@release_argument
@click.argument('parameter', nargs=-1)
@click.pass_obj
@click.option('--execute', is_flag=True)
def apply_autoscaling(config, template, application, version, release, parameter, execute):
    '''Apply Horizontal Pod Autoscaling to current deployment'''
    context = parse_parameters(parameter)
    context['application'] = application
    context['version'] = version
    context['release'] = release
    data = _render_template(template, context)

    cluster_id = config.get('kubernetes_cluster')
    namespace = config.get('kubernetes_namespace')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
    response = request(config, requests.post, path, json=data)
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


@cli.command('traffic')
@application_argument
@click.argument('release', required=False)
@click.argument('percent', required=False, type=click.IntRange(0, 100))
@click.pass_obj
@click.option('--execute', is_flag=True)
def traffic(config, application, release, percent, execute):
    cluster_id = config.get('kubernetes_cluster')
    namespace = config.get('kubernetes_namespace')

    ingress = kubectl_get(namespace, 'ingresses', application)

    if release is None and percent is None:
        print(json.dumps(get_ingress_backends(ingress)))
        return

    backend = '{}-{}'.format(application, release)

    backend_weights = calculate_backend_weights(ingress, backend, percent)

    if len(backend_weights) == 0:
        error('Failed to find ingress backends {}'.format(backend))
        raise click.Abort()

    # update ingress resource
    resources_update = ResourcesUpdate()
    resources_update.set_annotation(application,
                                    # ~1 == / in json patch
                                    INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY.replace('/', '~1'),
                                    json.dumps(backend_weights),
                                    'ingresses')
    path = '/kubernetes-clusters/{}/namespaces/{}/resources'.format(cluster_id, namespace)
    response = request(config, requests.patch, path, json=resources_update.to_dict())
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


def calculate_backend_weights(ingress, backend, percent):
    '''Get backends from an ingress object'''
    backend_weights = {}

    for rule in ingress['spec']['rules']:
        path_backends = {}
        for path in rule['http']['paths']:
            if path.get('path', '') in path_backends:
                path_backends[path.get('path', '')][path['backend']['serviceName']] = 0
            else:
                path_backends[path.get('path', '')] = {path['backend']['serviceName']: 0}

        for path, backends in path_backends.items():
            if backend in backends:
                for b in backends:
                    if b == backend:
                        weight = percent
                    else:
                        weight = (100 - percent) / (len(backends) - 1)
                    backends[b] = weight
                backend_weights = backends
                break

    return backend_weights


def get_ingress_backends(ingress):
    '''Get ingress backends along with their specified or calculated traffic
    weight'''

    backend_weights = json.loads(ingress['metadata'].get('annotations', {}).get(
        INGRESS_BACKEND_WEIGHT_ANNOTATION_KEY, "{}"))

    backends = {}

    for rule in ingress['spec']['rules']:
        path_sum_count = {}

        # get backend weight sum and count of all backends for all paths
        for path in rule['http']['paths']:
            p = path.get('path', '')
            if p not in path_sum_count:
                sc = {'sum': 0, 'count': 0}
                path_sum_count[p] = sc
            else:
                sc = path_sum_count[p]

            sc['sum'] += backend_weights.get(path['backend']['serviceName'], 0)
            sc['count'] += 1

        # calculate traffic weight for each backend
        for path in rule['http']['paths']:
            p = path.get('path', '')
            sc = path_sum_count[p]
            backend = path['backend']['serviceName']
            weight = backend_weights.get(backend, 0)
            if sc['sum'] <= 0:
                # special case: all weights are zero, every backend gets same traffic
                backends[backend] = int(100 / sc['count'])
            else:
                backends[backend] = int(weight / sc['sum'] * 100)

    return backends


@cli.command('delete')
@click.argument('type', type=click.Choice(['kubernetes', 'cloudformation']))
@click.argument('resource')
@click.pass_obj
@click.option('--execute', is_flag=True)
def delete(config, type, resource, execute):
    '''Delete a Kubernetes resource or Cloud Formation stack'''

    if type == 'kubernetes':
        parts = resource.split('/')
        if len(parts) != 2:
            error('Kubernetes resource must be KIND/NAME')
            raise click.Abort()

        kind, name = parts

        info('Deleting Kubernetes {} {}..'.format(kind, name))

        if kind == 'deployments':
            deployment = kubectl_get(config['kubernetes_namespace'], 'deployments', name)
            delete_deployment(config, deployment, execute)
            return
        else:
            cluster_id = config['kubernetes_cluster']
            namespace = config['kubernetes_namespace']
            path = '/kubernetes-clusters/{}/namespaces/{}/{}/{}'.format(
                cluster_id, namespace, kind, name)
    else:
        info('Deleting Cloud Formation stack {}..'.format(resource))
        aws_account = config.get('aws_account')
        aws_region = config.get('aws_region')
        path = '/aws-accounts/{}/regions/{}/cloudformation-stacks/{}'.format(
            aws_account, aws_region, resource)

    response = request(config, requests.delete, path)
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)


def get_replicas(name, namespace):
    '''Get number of replicas for a deployment'''
    deployment = kubectl_get(namespace, 'deployments', name)
    return deployment.get('status', {}).get('replicas', 0)


def delete_deployment(config, deployment, execute):
    '''Delete deployment by first scaling down to 0, deleting the deployment
    resource and any replicaset resources owned by the deployment.'''
    cluster_id = config.get('kubernetes_cluster')
    name = deployment['metadata']['name']
    namespace = deployment['metadata']['namespace']

    # scale deployment to 0 before deleting
    _scale_deployment(config, name, namespace, 0, execute)

    # with for deployment to be scaled down to 0
    timeout = DEFAULT_RESOURCE_DELETION_TIMEOUT
    maxtime = time.time() + timeout
    while get_replicas(name, namespace) > 0:
        if time.time() > maxtime:
            error('Timed out after {:d}s waiting for deployment to scale down'.format(timeout))
            return

    # get replicasets owned by the deployment
    replicasets = kubectl_get(namespace, 'replicasets')
    owned_rs = get_owned_replicasets(deployment, replicasets['items'])

    # delete deployment
    info('Deleting deployment {}..'.format(name))
    path = '/kubernetes-clusters/{}/namespaces/{}/deployments/{}'.format(
        cluster_id, namespace, name)
    response = request(config, requests.delete, path)
    change_request_id = response.json()['id']

    if execute:
        approve_and_execute(config, change_request_id)
    else:
        print(change_request_id)

    # delete replicasets
    for rs in owned_rs:
        name = rs['metadata']['name']
        info('Deleting replicaset {}..'.format(name))
        path = '/kubernetes-clusters/{}/namespaces/{}/replicasets/{}'.format(
            cluster_id, namespace, name)
        response = request(config, requests.delete, path)
        change_request_id = response.json()['id']

        if execute:
            approve_and_execute(config, change_request_id)
        else:
            print(change_request_id)


def get_owned_replicasets(deployment, replicasets) -> list:
    '''Return all replicasets owned by a deployment'''
    owned = []
    for rs in replicasets:
        for owner in rs['metadata'].get('ownerReferences', []):
            if owner['uid'] == deployment['metadata']['uid']:
                owned.append(rs)
    return owned


@cli.command('delete-old-deployments')
@application_argument
@version_argument
@release_argument
@click.pass_obj
@click.option('--execute', is_flag=True)
def delete_old_deployments(config, application, version, release, execute):
    '''Delete old releases'''
    namespace = config.get('kubernetes_namespace')
    kubectl_login(config)

    data = kubectl_get(namespace, 'deployments', '-l', 'application={}'.format(application))
    deployments = data['items']
    target_deployment_name = '{}-{}-{}'.format(application, version, release)
    deployments_to_delete = []
    deployment_found = False

    for deployment in sorted(deployments, key=lambda d: d['metadata']['name'], reverse=True):
        deployment_name = deployment['metadata']['name']
        if deployment_name == target_deployment_name:
            deployment_found = True
        else:
            deployments_to_delete.append(deployment)

    if not deployment_found:
        error('Deployment {} was not found.'.format(target_deployment_name))
        raise click.Abort()

    for deployment in deployments_to_delete:
        delete_deployment(config, deployment, execute)


@cli.command('delete-old-services')
@application_argument
@version_argument
@release_argument
@click.pass_obj
@click.option('--execute', is_flag=True)
def delete_old_services(config, application, version, release, execute):
    '''Delete old releases'''
    namespace = config.get('kubernetes_namespace')
    kubectl_login(config)

    data = kubectl_get(namespace, 'services', '-l', 'application={}'.format(application))
    services = data['items']
    target_service_name = '{}-{}'.format(application, release)
    services_to_delete = []
    service_found = False

    for service in sorted(services, key=lambda d: d['metadata']['name'], reverse=True):
        service_name = service['metadata']['name']
        if service_name == target_service_name:
            service_found = True
        else:
            services_to_delete.append(service_name)

    if not service_found:
        error('Service {} was not found.'.format(target_service_name))
        raise click.Abort()

    for service_name in services_to_delete:
        info('Deleting service {}..'.format(service_name))
        cluster_id = config.get('kubernetes_cluster')
        namespace = config.get('kubernetes_namespace')
        path = '/kubernetes-clusters/{}/namespaces/{}/services/{}'.format(
            cluster_id, namespace, service_name)
        response = request(config, requests.delete, path)
        change_request_id = response.json()['id']

        if execute:
            approve_and_execute(config, change_request_id)
        else:
            print(change_request_id)


@cli.command('render-template')
@click.argument('template', type=click.File('r'))
@click.argument('parameter', nargs=-1)
@click.pass_obj
def render_template(config, template, parameter):
    '''Interpolate YAML Mustache template'''
    data = _render_template(template, parse_parameters(parameter))
    print(yaml.safe_dump(data))


@cli.command('list-change-requests')
@click.pass_obj
def list_change_requests(config):
    '''List change requests'''
    response = request(config, requests.get, '/change-requests')
    items = response.json()['items']
    rows = []
    for row in items:
        rows.append(row)
    print_table('id platform kind user executed'.split(), rows)


@cli.command('get-change-request')
@click.argument('change_request_id', nargs=-1)
@click.pass_obj
def get_change_request(config, change_request_id):
    '''Get one or more change requests'''
    for id_ in change_request_id:
        path = '/change-requests/{}'.format(id_)
        response = request(config, requests.get, path)
        data = response.json()
        print(yaml.safe_dump(data, default_flow_style=False))


@cli.command('approve-change-request')
@click.argument('change_request_id', nargs=-1)
@click.pass_obj
def approve_change_request(config, change_request_id):
    '''Approve one or more change requests'''
    for id_ in change_request_id:
        approve(config, id_)


@cli.command('list-approvals')
@click.argument('change_request_id')
@click.pass_obj
def list_approvals(config, change_request_id):
    '''Show approvals for given change request'''
    path = '/change-requests/{}/approvals'.format(change_request_id)
    response = request(config, requests.get, path)
    items = response.json()['items']
    rows = []
    for row in items:
        rows.append(row)
    print_table('user created_at'.split(), rows)


@cli.command('execute-change-request')
@click.argument('change_request_id', nargs=-1)
@click.pass_obj
def execute_change_request(config, change_request_id):
    '''Execute one or more change requests'''
    for id_ in change_request_id:
        execute(config, id_)


@cli.command('encrypt')
@click.option('--use-kms', is_flag=True)
@click.option('--kms-keyid')
@click.pass_obj
def encrypt(config, use_kms, kms_keyid):
    '''Encrypt plain text (read from stdin) for deployment configuration'''
    plain_text = sys.stdin.read()

    if use_kms:
        if not kms_keyid:
            cluster = config.get('kubernetes_cluster')
            local_id = cluster.rsplit(':')[-1]
            kms_keyid = 'alias/{}-deployment-secret'.format(local_id)
        try:
            kms = boto3.client("kms")
            encrypted = kms.encrypt(KeyId=kms_keyid,
                                    Plaintext=plain_text.encode())
            encrypted = base64.b64encode(encrypted['CiphertextBlob'])
            account_name = get_aws_account_name()
            print("deployment-secret:{account_name}:{encrypted}".format(
                account_name=account_name,
                encrypted=encrypted.decode()
            ))
        except boto_exceptions.ClientError as exception:
            error_dict = exception.response["Error"]
            error_code = error_dict["Code"]
            if error_code == "NotFoundException":
                message = "KMS key '{}' not found".format(kms_keyid)
            elif error_code == "ExpiredTokenException":
                message = "Not logged in to AWS"
            else:
                message = "Failed to encrypt with KMS"
            error(message)
            sys.exit(1)
    else:
        api_url = config.get('deploy_api')
        url = '{}/secrets'.format(api_url)
        response = request(config, requests.post, url,
                           json={'plaintext': plain_text})
        encrypted = response.json()['data']
        print("deployment-secret:autobahn-encrypted:{}".format(encrypted))


def copy_template(template_path: Path, path: Path, variables: dict):
    for d in template_path.iterdir():
        target_path = path / d.relative_to(template_path)
        if d.is_dir():
            copy_template(d, target_path, variables)
        elif target_path.exists():
            # better not overwrite any existing files!
            raise click.UsageError('Target file "{}" already exists. Aborting!'.format(target_path))
        else:
            with Action('Writing {}..'.format(target_path)):
                # pathlib,Path.parent.mkdir keyword argument "exist_ok" where implemented
                # in python 3.5 and backported only to python 2.7 pathlib2 - but not to python 3.4 pathlib
                try:
                    target_path.parent.mkdir(parents=True)
                except FileExistsError:
                    pass
                except IOError as e:
                    if e.errno != errno.EEXIST:
                        raise
                with d.open() as fd:
                    contents = fd.read()
                template = string.Template(contents)
                contents = template.safe_substitute(variables)
                with target_path.open('w') as fd:
                    fd.write(contents)


def read_senza_variables(fd):
    variables = {}
    data = yaml.safe_load(fd)

    senza_info = data.get('SenzaInfo')
    if not senza_info:
        raise click.UsageError('Senza file has not property "SenzaInfo"')

    variables['application'] = senza_info.get('StackName')

    components = data.get('SenzaComponents')
    if not components:
        raise click.UsageError('Senza file has no property "SenzaComponents"')

    for component in components:
        for name, definition in component.items():
            type_ = definition.get('Type')
            if not type_:
                raise click.UsageError('Missing "Type" property in Senza component "{}"'.format(name))
            if type_ == 'Senza::TaupageAutoScalingGroup':
                taupage_config = definition.get('TaupageConfig')
                if not taupage_config:
                    raise click.UsageError('Missing "TaupageConfig" property in Senza component "{}"'.format(name))
                # just assume half the main memory of the EC2 instance type
                variables['memory'] = '{}Mi'.format(round(
                                      EC2_INSTANCE_MEMORY.get(taupage_config.get('InstanceType'), 1000) * 0.5))
                variables['image'] = taupage_config.get('source', '').replace('{{Arguments.ImageVersion}}',
                                                                              '{{ version }}')
                variables['env'] = taupage_config.get('environment', {})
                application_id = taupage_config.get('application_id')
                if application_id:
                    # overwrites default StackName
                    variables['application'] = application_id
            elif type_ in ('Senza::WeightedDnsElasticLoadBalancer', 'Senza::WeightedDnsElasticLoadBalancerV2'):
                variables['port'] = definition.get('HTTPPort')
                variables['health_check_path'] = definition.get('HealthCheckPath') or '/health'
                main_domain = definition.get('MainDomain')
                if main_domain:
                    variables['dnsname'] = main_domain

    if 'dnsname' not in variables:
        variables['dnsname'] = '{{ application }}.foo.example.org'

    return variables


def prepare_variables(variables: dict):
    env = []
    for key, val in sorted(variables.get('env', {}).items()):
        env.append({'name': str(key), 'value': str(val)})
    # FIXME: the indent is hardcoded and depends on formatting of deployment.yaml :-(
    variables['env'] = textwrap.indent(yaml.dump(env, default_flow_style=False), ' ' * 12)
    return variables


@cli.command('init')
@click.argument('directory', nargs=-1)
@click.option('-t', '--template', help='Use a custom template (default: webapp)',
              metavar='TEMPLATE_ID', default='webapp')
@click.option('--from-senza', help='Convert Senza definition',
              type=click.File('r'), metavar='SENZA_FILE')
@click.option('--kubernetes-cluster')
@click.pass_obj
def init(config, directory, template, from_senza, kubernetes_cluster):
    '''Initialize a new deploy folder with Kubernetes manifests'''
    if directory:
        path = Path(directory[0])
    else:
        path = Path('.')

    if from_senza:
        variables = read_senza_variables(from_senza)
        template = 'senza'
    else:
        variables = {}

    if kubernetes_cluster:
        cluster_id = kubernetes_cluster
    else:
        info('Please select your target Kubernetes cluster')
        subprocess.call(['zkubectl', 'list-clusters'])
        cluster_id = ''
        while len(cluster_id.split(':')) != 4:
            cluster_id = click.prompt('Kubernetes Cluster ID to use')

    variables['cluster_id'] = cluster_id
    parts = cluster_id.split(':')
    variables['account_id'] = ':'.join(parts[:2])
    variables['region'] = parts[2]

    template_path = Path(__file__).parent / 'templates' / template
    variables = prepare_variables(variables)
    copy_template(template_path, path, variables)

    print()

    notes = path / 'NOTES.txt'
    with notes.open() as fd:
        print(fd.read())


def get_prev_release(services, current_release):
    if len(services) == 0:
        prev_release = current_release
    else:
        sorted(services, key=lambda s: int(s["metadata"].get("labels", {}).get("release", "0")))
        prev_release = services[-1]["metadata"].get("labels", {}).get("release", None) or current_release
    return prev_release


def main():
    cli()
